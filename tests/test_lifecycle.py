import os
import tempfile
import unittest
from unittest.mock import patch

import database
from generate_prover import generate_prover_toml
import integrity
from support import insert_test_credential
import zk_engine

CSRF = 'test-token'
ALICE, TECHCORP, ALEX, SARA = 1, 2, 3, 4  # job 1 belongs to Alice


class HiringLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(database, 'DB_PATH', os.path.join(self.temp.name, 'test.db'))
        self.db_patch.start()
        database.init_db()
        import app
        self.client = app.app.test_client()
        # Reissuing a credential needs the Noir toolchain; a stand-in records each call.
        self.issue_patch = patch.object(zk_engine, 'issue_credential', side_effect=insert_test_credential)
        self.issue_credential = self.issue_patch.start()
        self.alex_app = self.execute(
            'INSERT INTO applications(job_id, freelancer_id, bid_amount, proof_verified) VALUES (1, ?, 800, 1)', (ALEX,))
        self.sara_app = self.execute(
            'INSERT INTO applications(job_id, freelancer_id, bid_amount, proof_verified) VALUES (1, ?, 700, 1)', (SARA,))

    def tearDown(self):
        self.issue_patch.stop()
        self.db_patch.stop()
        self.temp.cleanup()

    def execute(self, sql, params=()):
        conn = database.get_db_connection()
        try:
            cursor = conn.execute(sql, params)
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    def one(self, sql, params=()):
        conn = database.get_db_connection()
        try:
            return conn.execute(sql, params).fetchone()
        finally:
            conn.close()

    def as_user(self, user_id):
        with self.client.session_transaction() as session:
            session['user_id'] = user_id
            session['csrf_token'] = CSRF

    def post(self, path, **data):
        return self.client.post(path, data={'csrf_token': CSRF, **data})

    def hire_and_deliver(self):
        self.as_user(ALICE)
        self.post(f'/applications/{self.alex_app}/accept')
        self.as_user(ALEX)
        self.post('/jobs/1/deliver')

    def test_accept_hires_one_and_declines_the_rest(self):
        self.as_user(ALICE)
        self.post(f'/applications/{self.alex_app}/accept')
        job = self.one('SELECT * FROM jobs WHERE id = 1')
        self.assertEqual((job['status'], job['hired_freelancer_id']), ('in_progress', ALEX))
        self.assertIsNotNone(job['accepted_at'])
        self.assertEqual(self.one('SELECT status FROM applications WHERE id = ?', (self.alex_app,))[0], 'accepted')
        self.assertEqual(self.one('SELECT status FROM applications WHERE id = ?', (self.sara_app,))[0], 'rejected')
        # A second acceptance on the now-hired job changes nothing.
        self.post(f'/applications/{self.sara_app}/accept')
        self.assertEqual(self.one('SELECT hired_freelancer_id FROM jobs WHERE id = 1')[0], ALEX)

    def test_only_the_owner_can_hire_and_only_verified_applicants(self):
        self.as_user(TECHCORP)
        self.assertEqual(self.post(f'/applications/{self.alex_app}/accept').status_code, 404)
        self.as_user(ALEX)
        self.post(f'/applications/{self.alex_app}/accept')
        self.as_user(ALICE)
        self.execute('UPDATE applications SET proof_verified = 0 WHERE id = ?', (self.alex_app,))
        self.post(f'/applications/{self.alex_app}/accept')
        self.assertEqual(self.one('SELECT status FROM jobs WHERE id = 1')[0], 'open')

    def test_decline_and_withdraw(self):
        self.as_user(ALICE)
        self.post(f'/applications/{self.sara_app}/reject')
        self.assertEqual(self.one('SELECT status FROM applications WHERE id = ?', (self.sara_app,))[0], 'rejected')
        self.as_user(SARA)
        self.assertEqual(self.post(f'/applications/{self.alex_app}/withdraw').status_code, 404)
        self.as_user(ALEX)
        self.post(f'/applications/{self.alex_app}/withdraw')
        self.assertEqual(self.one('SELECT status FROM applications WHERE id = ?', (self.alex_app,))[0], 'withdrawn')

    def test_only_the_hired_freelancer_delivers_and_only_delivered_work_completes(self):
        self.as_user(ALICE)
        self.post(f'/applications/{self.alex_app}/accept')
        self.post('/jobs/1/complete', rating='5')
        self.assertEqual(self.one('SELECT status FROM jobs WHERE id = 1')[0], 'in_progress')
        self.as_user(SARA)
        self.assertEqual(self.post('/jobs/1/deliver').status_code, 404)
        self.as_user(ALEX)
        self.post('/jobs/1/deliver')
        self.assertIsNotNone(self.one('SELECT delivered_at FROM jobs WHERE id = 1')[0])

    def test_review_feeds_the_freelancers_private_history_and_next_proof(self):
        before = self.one('SELECT * FROM users_with_reputation WHERE id = ?', (ALEX,))
        self.hire_and_deliver()
        self.as_user(ALICE)
        self.post('/jobs/1/complete', rating='4', comment='Solid work', disputed='1')

        self.assertEqual(self.one('SELECT status FROM jobs WHERE id = 1')[0], 'completed')
        review = self.one('SELECT * FROM reviews WHERE job_id = 1 AND reviewer_id = ?', (ALICE,))
        self.assertEqual((review['reviewee_id'], review['rating_scaled'], review['disputed']), (ALEX, 400, 1))
        record = self.one("SELECT * FROM reputation_records WHERE job_reference = 'JOB-1'")
        self.assertEqual((record['freelancer_id'], record['client_id'], record['rating_scaled'],
                          record['on_time'], record['disputed'], record['is_demo']), (ALEX, ALICE, 400, 1, 1, 0))
        after = self.one('SELECT * FROM users_with_reputation WHERE id = ?', (ALEX,))
        self.assertEqual(after['completed_jobs'], before['completed_jobs'] + 1)
        self.assertEqual(after['dispute_count'], before['dispute_count'] + 1)
        self.issue_credential.assert_called_once_with(ALEX)
        credential = self.one('SELECT * FROM credentials WHERE freelancer_id = ? ORDER BY version DESC', (ALEX,))
        self.assertEqual(credential['record_count'], after['completed_jobs'])
        witness = generate_prover_toml(ALEX, 2, os.path.join(self.temp.name, 'Prover.toml'))['private_inputs']
        self.assertEqual(sum(witness['valid']), after['completed_jobs'])
        self.assertIn(400, witness['ratings'])
        # Completing twice must not add a second record.
        self.post('/jobs/1/complete', rating='5')
        self.assertEqual(self.one("SELECT COUNT(*) FROM reputation_records WHERE job_reference = 'JOB-1'")[0], 1)
        # The new review, record and credential are all signed and pass the integrity audit.
        self.as_user(ALEX)
        self.post('/jobs/1/review-client', rating='4')
        conn = database.get_db_connection()
        try:
            self.assertEqual(integrity.audit(conn), [])
            self.assertEqual(len(integrity.verified_history(conn, ALEX)), after['completed_jobs'])
        finally:
            conn.close()

    def test_job_still_completes_if_credential_cannot_be_reissued(self):
        self.hire_and_deliver()
        self.as_user(ALICE)
        self.issue_credential.side_effect = RuntimeError('nargo was not found')
        page = self.client.post('/jobs/1/complete', data={'csrf_token': CSRF, 'rating': '5'},
                                follow_redirects=True).get_data(as_text=True)
        self.assertEqual(self.one('SELECT status FROM jobs WHERE id = 1')[0], 'completed')
        self.assertIsNotNone(self.one("SELECT 1 FROM reputation_records WHERE job_reference = 'JOB-1'"))
        self.assertIn('could not be reissued yet', page)

    def test_late_delivery_is_recorded_as_not_on_time(self):
        self.as_user(ALICE)
        self.post(f'/applications/{self.alex_app}/accept')
        self.execute("UPDATE jobs SET accepted_at = datetime('now', '-30 days') WHERE id = 1")
        self.as_user(ALEX)
        self.post('/jobs/1/deliver')
        self.as_user(ALICE)
        self.post('/jobs/1/complete', rating='5')
        self.assertEqual(self.one("SELECT on_time FROM reputation_records WHERE job_reference = 'JOB-1'")[0], 0)

    def test_freelancer_reviews_client_once_and_rating_is_public(self):
        self.hire_and_deliver()
        self.post('/jobs/1/review-client', rating='4')  # not completed yet
        self.assertIsNone(self.one('SELECT 1 FROM reviews WHERE reviewer_id = ?', (ALEX,)))
        self.as_user(ALICE)
        self.post('/jobs/1/complete', rating='5')
        self.as_user(ALEX)
        self.post('/jobs/1/review-client', rating='4', comment='Clear brief')
        self.post('/jobs/1/review-client', rating='1')
        self.assertEqual(self.one('SELECT COUNT(*), MAX(rating_scaled) FROM reviews WHERE reviewer_id = ?', (ALEX,))[:], (1, 400))
        self.as_user(SARA)
        self.assertIn('4.0 (Client, 1 review)', self.client.get('/').get_data(as_text=True))

    def test_applicants_and_private_stats_stay_private(self):
        self.as_user(SARA)
        page = self.client.get('/jobs/1').get_data(as_text=True)
        self.assertNotIn('@alex_dev', page)
        self.as_user(ALICE)
        page = self.client.get('/jobs/1').get_data(as_text=True)
        self.assertIn('@alex_dev', page)
        self.assertNotIn('Your Private Reputation', page)

    def test_dashboards_render_for_each_role(self):
        self.hire_and_deliver()
        page = self.client.get('/dashboard').get_data(as_text=True)
        self.assertIn('Your Private Reputation', page)
        self.assertIn('Delivered - awaiting approval', page)
        self.as_user(ALICE)
        page = self.client.get('/dashboard').get_data(as_text=True)
        self.assertIn('Approve &amp; review', page)
        self.assertEqual(self.client.get('/jobs/999').status_code, 404)


if __name__ == '__main__':
    unittest.main()
