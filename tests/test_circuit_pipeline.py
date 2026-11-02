import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import database
from generate_circuit import generate_main_nr
from generate_prover import generate_prover_toml
import zk_engine

NARGO = shutil.which('nargo')


class FullHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_patch = patch.object(database, 'DB_PATH', str(self.root / 'test.db'))
        self.db_patch.start()
        database.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.temp.cleanup()

    def inputs(self, **kwargs):
        return generate_prover_toml(3, 1, self.root / 'Prover.toml', **kwargs)

    def test_every_record_including_oldest_is_exported_in_order(self):
        conn = database.get_db_connection()
        conn.execute('UPDATE reputation_records SET rating_scaled=100, on_time=0, disputed=1 WHERE id=1')
        conn.commit()
        records = database.get_reputation_records(conn, 3)
        conn.close()
        witness = self.inputs()['private_inputs']
        for i, row in enumerate(records):
            self.assertEqual([witness[k][i] for k in ('ratings', 'on_time', 'disputed', 'valid')],
                             [row['rating_scaled'], row['on_time'], row['disputed'], 1])
        for values in witness.values():
            self.assertEqual(len(values), 64)
            self.assertEqual(values[40:], [0] * 24)

    def test_full_capacity_allowed_and_overflow_rejected_without_writing(self):
        self.assertEqual(self.inputs(num_past_jobs=40)['private_inputs']['valid'], [1] * 40)
        original = (self.root / 'Prover.toml').read_text()
        with self.assertRaisesRegex(ValueError, 'no records were truncated'):
            self.inputs(num_past_jobs=39)
        self.assertEqual((self.root / 'Prover.toml').read_text(), original)

    def test_invalid_capacity_and_scale(self):
        for capacity in (0, 1, -1, 4097, True, 2.5):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                generate_main_nr(self.root / 'main.nr', capacity)
        with self.assertRaises(ValueError):
            self.inputs(rating_scale=10)

    def test_bad_public_requirements_are_rejected(self):
        for field, value in [('min_rating', 4.801), ('min_rating', 5.01),
                             ('min_on_time_rate', 101), ('min_completed_jobs', -1),
                             ('max_disputes', 2**32)]:
            conn = database.get_db_connection()
            old = conn.execute(f'SELECT {field} FROM jobs WHERE id=1').fetchone()[0]
            conn.execute(f'UPDATE jobs SET {field}=? WHERE id=1', (value,))
            conn.commit()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.inputs()
            conn.execute(f'UPDATE jobs SET {field}=? WHERE id=1', (old,))
            conn.commit()
            conn.close()

    def test_engine_uses_same_capacity_and_recompiles_existing_artifact(self):
        # A rejected execute stops before proving. This checks orchestration only.
        result = subprocess.CompletedProcess([], 1, '', 'constraint failure')
        fake_nargo = zk_engine.Tool('nargo')
        fake_bb = zk_engine.Tool('bb')
        with patch.object(zk_engine, 'CIRCUIT_DIR', str(self.root)), patch.object(
                zk_engine, 'get_toolchain', return_value=(fake_nargo, fake_bb)), patch.object(
                zk_engine, '_run', side_effect=[subprocess.CompletedProcess([], 0, '', ''), result]) as run:
            (self.root / 'target').mkdir()
            (self.root / 'target/circuit.json').write_text('old artifact')
            output = zk_engine.generate_and_verify_zk_proof(3, 1, num_past_jobs=40)
            self.assertFalse(output['success'])
            self.assertEqual(run.call_args_list[0].args[1], 'compile')
            self.assertIn('ratings: [u32; 40]', (self.root / 'src/main.nr').read_text())
            self.assertEqual(len(output['prover_data']['private_inputs']['ratings']), 40)

    def test_toolchain_versions_are_enforced(self):
        nargo, bb = zk_engine.Tool('nargo'), zk_engine.Tool('bb')
        good_nargo = subprocess.CompletedProcess([], 0, 'nargo version = 1.0.0-beta.26', '')
        good_bb = subprocess.CompletedProcess([], 0, '5.2.0', '')
        with patch.object(zk_engine, '_resolve_tool', side_effect=[nargo, bb]), patch.object(
                zk_engine, '_run', side_effect=[good_nargo, good_bb]):
            self.assertEqual(zk_engine.get_toolchain(), (nargo, bb))
        wrong_bb = subprocess.CompletedProcess([], 0, '6.0.0', '')
        with patch.object(zk_engine, '_resolve_tool', side_effect=[nargo, bb]), patch.object(
                zk_engine, '_run', side_effect=[good_nargo, wrong_bb]), self.assertRaisesRegex(
                RuntimeError, 'Expected Barretenberg 5.2.0'):
            zk_engine.get_toolchain()

    @unittest.skipUnless(NARGO, 'Nargo is not installed; actual circuit execution not tested')
    def test_noir_tests_and_database_witness(self):
        (self.root / 'Nargo.toml').write_text('[package]\nname="test_circuit"\ntype="bin"\nauthors=[]\n[dependencies]\n')
        generate_main_nr(self.root / 'src/main.nr')
        conn = database.get_db_connection()
        conn.execute('UPDATE jobs SET min_rating=4.9 WHERE id=1')
        conn.commit()
        conn.close()
        self.inputs()
        for command in ([NARGO, 'test'], [NARGO, 'execute', 'witness']):
            result = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Make the oldest job poor: the circuit must include it, not just recent jobs.
        conn = database.get_db_connection()
        conn.execute('UPDATE reputation_records SET rating_scaled=100 WHERE id=1')
        conn.commit()
        conn.close()
        self.inputs()
        result = subprocess.run([NARGO, 'execute', 'witness'], cwd=self.root, capture_output=True, text=True, timeout=180)
        self.assertNotEqual(result.returncode, 0, 'Oldest record was ignored')


if __name__ == '__main__':
    unittest.main()
