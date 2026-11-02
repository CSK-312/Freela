import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import database
from support import insert_test_credential
import zk_engine


class VerificationResultsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(database, 'DB_PATH', os.path.join(self.temp.name, 'test.db'))
        self.db_patch.start()
        database.init_db()
        insert_test_credential(3)
        import app
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session['user_id'] = 3  # alex_dev, freelancer
            session['csrf_token'] = 'test-token'

    def tearDown(self):
        self.db_patch.stop()
        self.temp.cleanup()

    def rows(self):
        conn = database.get_db_connection()
        try:
            return conn.execute('SELECT * FROM applications').fetchall()
        finally:
            conn.close()

    def submit(self, result):
        with patch.object(zk_engine, 'generate_and_verify_zk_proof', return_value=result):
            return self.client.post('/jobs/1/apply', data={
                'bid_amount': '100', 'csrf_token': 'test-token', 'zk_proof_hex': 'forged-client-proof',
                'zk_public_inputs': '{}'
            }, follow_redirects=True).get_data(as_text=True)

    def test_failed_missing_or_nonboolean_verification_never_saves(self):
        for result in ({'success': False, 'verified': True},
                       {'success': True, 'verified': False},
                       {'success': True}, {'success': True, 'verified': 'false'},
                       {'success': True, 'verified': True, 'proof_hex': ''}):
            with self.subTest(result=result):
                page = self.submit(result)
                self.assertEqual(self.rows(), [])
                self.assertIn('Application not submitted', page)
                self.assertNotIn('ZK Proof Verified', page)

    def test_verifier_exception_never_saves(self):
        with patch.object(zk_engine, 'generate_and_verify_zk_proof', side_effect=RuntimeError('Verifier unavailable')):
            self.client.post('/jobs/1/apply', data={'bid_amount': '100', 'csrf_token': 'test-token'})
        self.assertEqual(self.rows(), [])

    def test_success_saves_server_proof_and_displays_verified(self):
        page = self.submit({'success': True, 'verified': True, 'proof_hex': '0x1234',
                            'prover_data': {'public_inputs': {'min_rating_scaled': 480}}})
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['proof_verified'], 1)
        self.assertEqual(rows[0]['zk_proof_hex'], '0x1234')
        self.assertIn('ZK Proof Verified', page)

    def test_old_unverified_application_is_not_labelled_verified(self):
        conn = database.get_db_connection()
        conn.execute('INSERT INTO applications(job_id, freelancer_id, bid_amount, proof_verified) VALUES(1,3,100,0)')
        conn.commit()
        conn.close()
        page = self.client.get('/dashboard').get_data(as_text=True)
        self.assertIn('Not verified', page)
        self.assertNotIn('ZK Proof Verified', page)

    def fake_engine(self, verify_code=0, verify_message='Proof verified successfully', public_inputs=None):
        """Run the real engine with the Noir/Barretenberg calls replaced."""
        root = Path(self.temp.name)
        package = root / 'circuit'
        (package / 'src').mkdir(parents=True, exist_ok=True)
        (package / 'target').mkdir(exist_ok=True)
        (package / 'Nargo.toml').write_text('[package]\n')
        (package / 'src/main.nr').write_text('// stand-in\n')
        (package / 'target/circuit.json').write_text('{}')
        vk = root / 'trusted.vk'
        vk.write_bytes(b'pinned-vk')
        build = zk_engine.Build(zk_engine.Tool('nargo'), zk_engine.Tool('bb'), 64, str(vk), 'vkhash')
        expected = [480, 25, 95, 1, 1, 3, int('1' * 64, 16)]  # job 1 thresholds, job, applicant, credential

        def fake_run(tool, *args, cwd=None, timeout=None):
            if args[0] == 'prove':
                (Path(cwd) / 'proof').mkdir()
                (Path(cwd) / 'proof/proof').write_bytes(b'proof-bytes')
                values = expected if public_inputs is None else public_inputs
                (Path(cwd) / 'proof/public_inputs').write_bytes(b''.join(v.to_bytes(32, 'big') for v in values))
            if args[0] == 'verify':
                self.assertEqual(Path(cwd, 'trusted_vk').read_bytes(), b'pinned-vk')
                return subprocess.CompletedProcess([], verify_code, verify_message, '')
            return subprocess.CompletedProcess([], 0, '', '')

        runs = root / 'runs'
        with patch.object(zk_engine, 'CIRCUIT_DIR', str(package)), patch.object(zk_engine, 'RUNS_DIR', str(runs)), \
                patch.object(zk_engine, 'prepare_circuits', return_value=build), patch.object(zk_engine, '_run', side_effect=fake_run):
            result = zk_engine.generate_and_verify_zk_proof(3, 1)
        self.assertEqual(list(runs.iterdir()), [], 'per-request working folder was not removed')
        return result

    def test_engine_returns_failure_when_verifier_rejects(self):
        for code, message in [(1, 'Proof verified successfully'), (0, 'verification failed')]:
            with self.subTest(code=code):
                result = self.fake_engine(verify_code=code, verify_message=message)
                self.assertFalse(result['success'])
                self.assertFalse(result['verified'])
                self.assertNotIn('proof_hex', result)

    def test_engine_rejects_valid_proof_about_something_else(self):
        for index, value in [(4, 2), (5, 4), (6, 99), (0, 100)]:  # other job, applicant, credential, threshold
            with self.subTest(index=index):
                inputs = [480, 25, 95, 1, 1, 3, int('1' * 64, 16)]
                inputs[index] = value
                result = self.fake_engine(public_inputs=inputs)
                self.assertFalse(result['success'])
                self.assertIn('do not match', result['error'])

    def test_engine_success_reports_credential_and_pinned_key(self):
        result = self.fake_engine()
        self.assertTrue(result['success'])
        self.assertEqual(result['proof_hex'], '0x' + b'proof-bytes'.hex())
        self.assertEqual(result['vk_hash'], 'vkhash')
        self.assertEqual(result['credential_id'], self.rows_credential_id())

    def rows_credential_id(self):
        conn = database.get_db_connection()
        try:
            return conn.execute('SELECT id FROM credentials WHERE freelancer_id = 3').fetchone()[0]
        finally:
            conn.close()

    def test_first_application_issues_initial_credential(self):
        conn = database.get_db_connection()
        conn.execute('DELETE FROM credentials')
        conn.commit()
        conn.close()
        with patch.object(zk_engine, 'issue_credential', side_effect=insert_test_credential) as issue:
            self.submit({'success': True, 'verified': True, 'proof_hex': '0x12',
                         'prover_data': {'public_inputs': {}}, 'credential_id': 1, 'vk_hash': 'abc'})
            issue.assert_called_once_with(3)
            self.submit({'success': True, 'verified': True, 'proof_hex': '0x12', 'prover_data': {'public_inputs': {}}})
            issue.assert_called_once()
        row = self.rows()[0]
        self.assertEqual((row['credential_id'], row['vk_hash']), (1, 'abc'))

if __name__ == '__main__':
    unittest.main()
