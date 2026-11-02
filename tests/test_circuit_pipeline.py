import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import database
from generate_circuit import generate_main_nr, generate_commit_nr
from generate_prover import generate_prover_toml
from support import insert_test_credential
import zk_engine

PROJECT = Path(__file__).resolve().parent.parent


def _installed(name, home_path):
    found = shutil.which(name) or os.path.expanduser(home_path)
    return found if os.path.isfile(found) else None


NARGO = _installed('nargo', '~/.nargo/bin/nargo')
BB = _installed('bb', '~/.bb/bb')


class FullHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_patch = patch.object(database, 'DB_PATH', str(self.root / 'test.db'))
        self.db_patch.start()
        database.init_db()
        insert_test_credential(3)

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
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                generate_commit_nr(self.root / 'commit.nr', capacity)
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

    def test_public_inputs_bind_job_applicant_and_newest_credential(self):
        insert_test_credential(3)  # version 2 supersedes version 1
        result = self.inputs()
        conn = database.get_db_connection()
        current = database.get_current_credential(conn, 3)
        conn.close()
        self.assertEqual(current['version'], 2)
        self.assertEqual(result['credential_id'], current['id'])
        self.assertEqual({k: result['public_inputs'][k] for k in ('job_id', 'applicant_id', 'commitment')},
                         {'job_id': 1, 'applicant_id': 3, 'commitment': current['commitment']})
        self.assertIn(f'salt = "{current["salt"]}"', (self.root / 'Prover.toml').read_text())

    def test_missing_or_stale_credential_is_rejected(self):
        conn = database.get_db_connection()
        conn.execute('''INSERT INTO reputation_records
            (job_reference, freelancer_id, client_id, rating_scaled, on_time, disputed, completed_at)
            VALUES ('EXTRA-1', 3, 1, 500, 1, 0, '2026-06-01')''')
        conn.commit()
        conn.close()
        with self.assertRaisesRegex(ValueError, 'must be reissued'):
            self.inputs()
        with self.assertRaisesRegex(ValueError, 'No credential'):
            generate_prover_toml(4, 1, self.root / 'Prover.toml')

    def test_prepare_circuits_builds_both_packages_and_pins_vk_once(self):
        for name in ('circuit', 'circuit_commit'):
            (self.root / name).mkdir()
        calls = []

        def fake_run(tool, *args, cwd=None, timeout=None):
            calls.append((args[0], Path(cwd).name))
            if args[0] == 'write_vk':
                (Path(cwd) / 'target/vk').mkdir(parents=True)
                (Path(cwd) / 'target/vk/vk').write_bytes(b'vk')
            return subprocess.CompletedProcess([], 0, '', '')

        tools = (zk_engine.Tool('nargo'), zk_engine.Tool('bb'))
        with patch.object(zk_engine, 'CIRCUIT_DIR', str(self.root / 'circuit')), \
                patch.object(zk_engine, 'COMMIT_DIR', str(self.root / 'circuit_commit')), \
                patch.dict(zk_engine._builds, clear=True), \
                patch.object(zk_engine, 'get_toolchain', return_value=tools), \
                patch.object(zk_engine, '_run', side_effect=fake_run):
            build = zk_engine.prepare_circuits(40)
            self.assertIs(zk_engine.prepare_circuits(40), build)
        self.assertEqual(calls, [('compile', 'circuit'), ('compile', 'circuit_commit'), ('write_vk', 'circuit')])
        self.assertEqual(build.vk_hash, hashlib.sha256(b'vk').hexdigest())
        for name in ('circuit', 'circuit_commit'):
            self.assertIn('ratings: [u32; 40]', (self.root / name / 'src/main.nr').read_text())

    def test_issue_missing_skips_freelancers_with_credentials_or_no_history(self):
        conn = database.get_db_connection()
        conn.execute('DELETE FROM reputation_records WHERE freelancer_id = 7')
        conn.commit()
        conn.close()
        with patch.object(zk_engine, 'issue_credential', side_effect=lambda fid, cap: fid) as issue:
            issued = zk_engine.issue_missing_credentials()
        # 3 already has one (setUp); 7 has no history; clients never get one.
        self.assertEqual(sorted(issued), [4, 5, 6])
        self.assertEqual(issue.call_count, 3)

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
class RealToolchainTests(unittest.TestCase):
    """Runs the pinned Noir/Barretenberg tools on copies of the circuit packages."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [patch.object(database, 'DB_PATH', str(self.root / 'test.db')),
                        patch.dict(zk_engine._builds, clear=True)]
        for name, attribute in (('circuit', 'CIRCUIT_DIR'), ('circuit_commit', 'COMMIT_DIR')):
            (self.root / name).mkdir()
            shutil.copy2(PROJECT / name / 'Nargo.toml', self.root / name)
            self.patches.append(patch.object(zk_engine, attribute, str(self.root / name)))
        self.patches.append(patch.object(zk_engine, 'RUNS_DIR', str(self.root / 'runs')))
        for p in self.patches:
            p.start()
        database.init_db()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def sql(self, statement):
        conn = database.get_db_connection()
        conn.execute(statement)
        conn.commit()
        conn.close()

    def test_noir_tests_pass(self):
        generate_main_nr(self.root / 'circuit/src/main.nr')
        result = subprocess.run([NARGO, 'test'], cwd=self.root / 'circuit', capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(BB, 'Barretenberg is not installed; real proving not tested')
    def test_end_to_end_proof_and_tamper_detection(self):
        credential = zk_engine.issue_credential(3)
        self.assertEqual((credential['version'], credential['record_count']), (1, 40))

        result = zk_engine.generate_and_verify_zk_proof(3, 1)
        self.assertTrue(result['success'], result)
        self.assertTrue(result['verified'])
        self.assertEqual(len(result['vk_hash']), 64)
        self.assertEqual(list((self.root / 'runs').iterdir()), [])

        # Editing history after issuance (even improving it) breaks the commitment.
        self.sql('UPDATE reputation_records SET on_time=1 WHERE id=1')
        self.assertFalse(zk_engine.generate_and_verify_zk_proof(3, 1)['success'])

        # Once reissued over a poor oldest job, the circuit counts it: 4.9 is no longer met.
        self.sql('UPDATE reputation_records SET rating_scaled=100 WHERE id=1')
        self.sql('UPDATE jobs SET min_rating=4.9 WHERE id=1')
        zk_engine.issue_credential(3)
        self.assertFalse(zk_engine.generate_and_verify_zk_proof(3, 1)['success'])


if __name__ == '__main__':
    unittest.main()
