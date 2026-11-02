import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch

import database
import zk_engine

CSRF = 'test-token'


class AuthAndValidationTests(unittest.TestCase):
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

    def query(self, sql, params=()):
        conn = database.get_db_connection()
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def login_as(self, user_id):
        with self.client.session_transaction() as session:
            session['user_id'] = user_id
            session['csrf_token'] = CSRF

    def post(self, path, **data):
        with self.client.session_transaction() as session:
            session.setdefault('csrf_token', CSRF)
        return self.client.post(path, data={'csrf_token': CSRF, **data})

    def job_form(self, **overrides):
        form = {'title': 'Audit a Flask app', 'category': 'Web Development', 'description': 'Details',
                'budget': '500', 'delivery_days': '5', 'min_rating': '4.5',
                'min_completed_jobs': '10', 'min_on_time_rate': '90', 'max_disputes': '1'}
        form.update(overrides)
        return form

    def test_logged_out_visitors_are_sent_to_login(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/login'))
        self.assertEqual(self.client.get('/api/check-eligibility/1').status_code, 401)
        self.assertEqual(self.client.get('/login').status_code, 200)
        self.assertEqual(self.client.get('/register').status_code, 200)

    def test_demo_shortcuts_and_database_page_are_gone(self):
        self.login_as(3)
        for path in ('/switch-user/1', '/database'):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)

    def test_register_hashes_password_and_logs_in(self):
        response = self.post('/register', username='new_dev', password='longpassword', role='freelancer')
        self.assertEqual(response.status_code, 302)
        user = self.query("SELECT * FROM users WHERE username='new_dev'")[0]
        self.assertTrue(user['password_hash'].startswith('pbkdf2:sha256'))
        self.assertEqual(user['role'], 'freelancer')
        self.assertEqual(self.client.get('/').status_code, 200)

    def test_register_rejects_bad_input_and_duplicates(self):
        for form in ({'username': 'ALEX_DEV', 'password': 'longpassword', 'role': 'client'},
                     {'username': 'ab', 'password': 'longpassword', 'role': 'client'},
                     {'username': 'bad name', 'password': 'longpassword', 'role': 'client'},
                     {'username': 'shortpw', 'password': 'short', 'role': 'client'},
                     {'username': 'admin_wannabe', 'password': 'longpassword', 'role': 'admin'}):
            with self.subTest(form=form):
                self.assertEqual(self.post('/register', **form).status_code, 200)
        self.assertEqual(len(self.query('SELECT * FROM users')), 7)

    def test_login_checks_password_and_upgrades_legacy_hash(self):
        legacy = hashlib.sha256(b'password123').hexdigest()
        conn = database.get_db_connection()
        conn.execute('UPDATE users SET password_hash=? WHERE id=1', (legacy,))
        conn.commit()
        conn.close()
        self.assertEqual(self.post('/login', username='client_alice', password='wrong').status_code, 200)
        self.assertEqual(self.client.get('/').status_code, 302)
        self.assertEqual(self.post('/login', username='client_alice', password='password123').status_code, 302)
        self.assertEqual(self.client.get('/').status_code, 200)
        self.assertTrue(self.query('SELECT password_hash FROM users WHERE id=1')[0][0].startswith('pbkdf2:'))

    def test_logout_requires_post(self):
        self.login_as(3)
        self.assertEqual(self.client.get('/logout').status_code, 405)
        self.post('/logout')
        self.assertEqual(self.client.get('/').status_code, 302)

    def test_post_without_csrf_token_is_ignored(self):
        self.login_as(1)
        self.client.post('/jobs/new', data=self.job_form())
        self.client.post('/jobs/new', data={**self.job_form(), 'csrf_token': 'wrong'})
        self.assertEqual(len(self.query('SELECT * FROM jobs')), 6)

    def test_roles_are_enforced(self):
        self.login_as(3)  # freelancer
        self.post('/jobs/new', **self.job_form())
        self.assertEqual(len(self.query('SELECT * FROM jobs')), 6)
        self.login_as(1)  # client
        self.assertEqual(self.client.get('/api/check-eligibility/1').status_code, 403)
        with patch.object(zk_engine, 'generate_and_verify_zk_proof') as engine:
            self.post('/jobs/1/apply', bid_amount='100')
        engine.assert_not_called()
        self.assertEqual(self.query('SELECT * FROM applications'), [])

    def test_job_form_validation(self):
        self.login_as(1)
        for field, value in [('budget', 'abc'), ('budget', '-5'), ('budget', 'nan'), ('budget', '10.001'),
                             ('category', 'Hacking'), ('min_on_time_rate', '150'), ('min_rating', '5.5'),
                             ('min_rating', '4.555'), ('delivery_days', '0'), ('title', ''),
                             ('min_completed_jobs', '65')]:
            with self.subTest(field=field, value=value):
                self.assertEqual(self.post('/jobs/new', **self.job_form(**{field: value})).status_code, 400)
        self.assertEqual(len(self.query('SELECT * FROM jobs')), 6)
        self.assertEqual(self.post('/jobs/new', **self.job_form()).status_code, 302)
        job = self.query('SELECT * FROM jobs ORDER BY id DESC LIMIT 1')[0]
        self.assertEqual((job['client_id'], job['budget'], job['delivery_days']), (1, 500.0, 5))

    def test_apply_checks_input_and_job_status_before_proving(self):
        self.login_as(3)
        conn = database.get_db_connection()
        conn.execute("UPDATE jobs SET status='completed' WHERE id=2")
        conn.commit()
        conn.close()
        with patch.object(zk_engine, 'generate_and_verify_zk_proof') as engine:
            self.post('/jobs/1/apply', bid_amount='abc')
            self.post('/jobs/1/apply', bid_amount='0')
            self.post('/jobs/2/apply', bid_amount='100')
            self.assertEqual(self.post('/jobs/999/apply', bid_amount='100').status_code, 404)
            self.assertEqual(self.client.get('/api/check-eligibility/2').status_code, 404)
        engine.assert_not_called()
        self.assertEqual(self.query('SELECT * FROM applications'), [])

    def test_missing_pages_get_the_friendly_404(self):
        for user in (None, 3):
            if user:
                self.login_as(user)
            with self.subTest(user=user):
                response = self.client.get('/no-such-page')
                self.assertEqual(response.status_code, 404)
                self.assertIn('Page not found', response.get_data(as_text=True))

    def test_reputation_view_has_no_credentials(self):
        columns = [r[1] for r in self.query('PRAGMA table_info(users_with_reputation)')]
        self.assertNotIn('password_hash', columns)
        self.assertNotIn('email', columns)


if __name__ == '__main__':
    unittest.main()
