import os
import tempfile
import unittest
from unittest.mock import patch

import database
from generate_prover import generate_prover_toml
import integrity
from support import accept_edits, insert_test_credential
import zk_engine

CSRF = 'test-token'
ALICE, ALEX, SARA = 1, 3, 4


class SignatureTests(unittest.TestCase):
    """Rows changed outside the app are caught wherever ratings or eligibility are computed."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(database, 'DB_PATH', os.path.join(self.temp.name, 'test.db'))
        self.db_patch.start()
        database.init_db()
        insert_test_credential(ALEX)
        import app
        self.app = app
        self.client = app.app.test_client()

    def tearDown(self):
        self.db_patch.stop()
        self.temp.cleanup()

    def sql(self, statement, params=()):
        conn = database.get_db_connection()
        try:
            conn.execute(statement, params)
            conn.commit()
        finally:
            conn.close()

    def history(self, freelancer_id=ALEX):
        conn = database.get_db_connection()
        try:
            return integrity.verified_history(conn, freelancer_id)
        finally:
            conn.close()

    def problems(self):
        conn = database.get_db_connection()
        try:
            return integrity.audit(conn)
        finally:
            conn.close()

    def prove_inputs(self):
        return generate_prover_toml(ALEX, 1, os.path.join(self.temp.name, 'Prover.toml'))

    def add_completed_job_with_reviews(self):
        """Job 1, done by Alex, with a signed review each way, written the way the app writes them."""
        self.sql("UPDATE jobs SET status='completed', hired_freelancer_id=? WHERE id=1", (ALEX,))
        conn = database.get_db_connection()
        try:
            integrity.add_review(conn, 1, ALICE, ALEX, 500, 'Great', 0)
            integrity.add_review(conn, 1, ALEX, ALICE, 400, 'Clear brief')
            conn.commit()
        finally:
            conn.close()

    def test_untouched_database_passes(self):
        self.assertEqual(len(self.history()), 40)
        self.assertEqual(self.problems(), [])
        self.assertEqual(self.prove_inputs()['public_inputs']['applicant_id'], ALEX)

    def test_edited_record_is_caught_before_proving_and_in_previews(self):
        self.sql("UPDATE reputation_records SET rating_scaled=500, on_time=1 WHERE job_reference='DEMO-alex_dev-001'")
        with self.assertRaisesRegex(integrity.TamperError, 'DEMO-alex_dev-001 was changed'):
            self.prove_inputs()
        with self.assertRaises(integrity.TamperError):
            zk_engine.issue_credential(ALEX)
        with self.client.session_transaction() as session:
            session['user_id'] = ALEX
        self.assertEqual(self.client.get('/api/check-eligibility/1').status_code, 409)
        self.assertIn(b'failed its signature check', self.client.get('/dashboard').data)
        self.assertEqual([p['subject'] for p in self.problems()], ['alex_dev'])

    def test_deleted_record_breaks_the_chain(self):
        self.sql("DELETE FROM reputation_records WHERE job_reference='DEMO-alex_dev-010'")
        with self.assertRaisesRegex(integrity.TamperError, 'out of sequence'):
            self.history()

    def test_deleting_the_newest_records_is_caught_by_the_credential(self):
        # The remaining chain is internally valid; only the signed credential knows it was longer.
        self.sql("DELETE FROM reputation_records WHERE job_reference IN ('DEMO-alex_dev-039', 'DEMO-alex_dev-040')")
        self.assertEqual(len(self.history()), 38)
        with self.assertRaisesRegex(integrity.TamperError, 'no longer all in the history'):
            self.prove_inputs()

    def test_forged_or_copied_rows_are_rejected(self):
        # A new row with another row's chain hash and signature still fails: the hash covers its contents.
        donor = self.history()[-1]
        self.sql('''INSERT INTO reputation_records (job_reference, freelancer_id, client_id, rating_scaled, on_time,
            disputed, completed_at, chain_index, chain_hash, signature) VALUES ('FAKE-1', ?, ?, 500, 1, 0, '2026-12-01', 41, ?, ?)''',
                 (ALEX, ALICE, donor['chain_hash'], donor['signature']))
        with self.assertRaises(integrity.TamperError):
            self.history()
        # Moving Sara's signed records onto Alex fails too: owner and position are signed.
        self.sql("DELETE FROM reputation_records WHERE job_reference='FAKE-1'")
        self.sql("UPDATE reputation_records SET freelancer_id=?, chain_index=chain_index+40 WHERE freelancer_id=?", (ALEX, SARA))
        with self.assertRaises(integrity.TamperError):
            self.history()

    def test_edited_credential_is_rejected(self):
        self.sql("UPDATE credentials SET commitment=? WHERE freelancer_id=?", ('0x' + '3' * 64, ALEX))
        with self.assertRaisesRegex(integrity.TamperError, 'Credential v1 has an invalid signature'):
            self.prove_inputs()

    def test_edited_review_is_excluded_from_client_rating_and_flagged(self):
        self.add_completed_job_with_reviews()
        conn = database.get_db_connection()
        try:
            self.assertEqual(integrity.client_ratings(conn, [ALICE])[ALICE], {'client_rating': 4.0, 'client_review_count': 1})
        finally:
            conn.close()

        self.sql('UPDATE reviews SET rating_scaled=100 WHERE reviewer_id=?', (ALEX,))
        conn = database.get_db_connection()
        try:
            self.assertEqual(integrity.client_ratings(conn, [ALICE])[ALICE], {'client_rating': None, 'client_review_count': 0})
        finally:
            conn.close()
        with self.client.session_transaction() as session:
            session['user_id'] = ALICE
        page = self.client.get('/jobs/1').data
        self.assertIn(b'signature invalid, not counted', page)
        self.assertIn(b'no reviews yet', self.client.get('/dashboard').data)
        self.assertEqual([p['area'] for p in self.problems()], ['Review'])

    def test_admin_correction_makes_edited_history_provable_again(self):
        self.sql("UPDATE reputation_records SET rating_scaled=300 WHERE job_reference='DEMO-alex_dev-001'")
        accept_edits(ALEX)
        self.assertEqual(self.history()[0]['rating_scaled'], 300)
        with self.assertRaisesRegex(ValueError, 'No credential'):
            self.prove_inputs()
        insert_test_credential(ALEX)
        self.assertEqual(self.prove_inputs()['private_inputs']['ratings'][0], 300)

    def test_admin_page_reports_integrity(self):
        self.sql("INSERT INTO admins (id, username, password_hash) VALUES (1, 'test_admin', 'unused')")
        with self.client.session_transaction() as session:
            session['admin_id'] = 1
        self.assertIn(b'All signatures are valid', self.client.get('/admin').data)
        self.sql("UPDATE reputation_records SET disputed=0 WHERE freelancer_id=?", (SARA,))
        page = self.client.get('/admin').data
        self.assertIn(b'1 problem found', page)
        self.assertIn(b'sara_design', page)

    def test_signing_key_lives_outside_the_database_and_is_required(self):
        path = integrity.key_path()
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(database.DB_PATH, 'rb') as db:
            self.assertNotIn(b'PRIVATE KEY', db.read())
        os.rename(path, path + '.moved')
        with patch.dict(integrity._keys, clear=True), self.assertRaisesRegex(RuntimeError, 'Signing key .* is missing'):
            self.history()


if __name__ == '__main__':
    unittest.main()
