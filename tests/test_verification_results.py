import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import database
import zk_engine


class VerificationResultsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(database, 'DB_PATH', os.path.join(self.temp.name, 'test.db'))
        self.db_patch.start()
        database.init_db()
        import app
        self.client = app.app.test_client()

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
                'bid_amount': '100', 'zk_proof_hex': 'forged-client-proof',
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
            self.client.post('/jobs/1/apply', data={'bid_amount': '100'})
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
        page = self.client.get('/').get_data(as_text=True)
        self.assertIn('Not verified', page)
        self.assertNotIn('ZK Proof Verified', page)

    def test_engine_returns_failure_when_verifier_rejects(self):
        root = Path(self.temp.name) / 'circuit'
        proof_dir = root / 'target/proof'
        proof_dir.mkdir(parents=True)
        (proof_dir / 'proof').write_bytes(b'proof-test-fixture')
        for code, message in [(1, 'Proof verified successfully'), (0, 'verification failed')]:
            runs = [subprocess.CompletedProcess([], 0, '', '') for _ in range(3)]
            runs.append(subprocess.CompletedProcess([], code, '', message))
            with self.subTest(code=code), patch.object(zk_engine, 'CIRCUIT_DIR', str(root)), patch.object(
                    zk_engine, 'get_toolchain', return_value=(zk_engine.Tool('nargo'), zk_engine.Tool('bb'))), patch.object(
                    zk_engine, '_run', side_effect=runs):
                result = zk_engine.generate_and_verify_zk_proof(3, 1)
            self.assertFalse(result['success'])
            self.assertFalse(result['verified'])
            self.assertNotIn('proof_hex', result)


if __name__ == '__main__':
    unittest.main()
