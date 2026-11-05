import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import database
from generate_prover import generate_prover_toml
import integrity
from support import accept_edits, insert_test_credential


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path_patch = patch.object(database, 'DB_PATH', os.path.join(self.temp.name, 'demo.db'))
        self.path_patch.start()
        database.init_db()
        self.conn = database.get_db_connection()

    def tearDown(self):
        self.conn.close()
        self.path_patch.stop()
        self.temp.cleanup()

    def test_seed_and_idempotent_initialization(self):
        database.init_db()
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM reputation_records').fetchone()[0], 150)
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], 6)
        self.assertEqual(self.conn.execute('PRAGMA foreign_key_check').fetchall(), [])
        self.assertEqual(self.conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_reputation_derived_from_records_not_old_totals(self):
        self.conn.execute('UPDATE users SET rating_score=1, completed_jobs=999 WHERE id=3')
        self.conn.execute('UPDATE reputation_records SET rating_scaled=400, on_time=0, disputed=1 WHERE freelancer_id=3')
        row = self.conn.execute('SELECT * FROM users_with_reputation WHERE id=3').fetchone()
        self.assertEqual((row['rating_score'], row['completed_jobs'], row['on_time_rate'], row['dispute_count']), (4, 40, 0, 40))

    def test_foreign_keys_enabled(self):
        self.assertEqual(self.conn.execute('PRAGMA foreign_keys').fetchone()[0], 1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute('INSERT INTO applications(job_id, freelancer_id) VALUES (99999, 3)')

    def test_duplicate_applications_rejected(self):
        self.conn.execute('INSERT INTO applications(job_id, freelancer_id) VALUES (1, 3)')
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute('INSERT INTO applications(job_id, freelancer_id) VALUES (1, 3)')

    def test_invalid_records_rejected(self):
        for column, value in [('rating_scaled', 501), ('rating_scaled', 99),
                              ('rating_scaled', 490.5), ('on_time', 2), ('disputed', -1),
                              ('completed_at', '2026-02-30'), ('completed_at', ''),
                              ('freelancer_id', 1), ('client_id', 3), ('freelancer_id', 9999)]:
            with self.subTest(column=column, value=value), self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute(f'UPDATE reputation_records SET {column}=? WHERE id=1', (value,))

    def test_duplicate_history_and_role_changes_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute('UPDATE reputation_records SET job_reference=(SELECT job_reference FROM reputation_records WHERE id=1) WHERE id=2')
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE users SET role='client' WHERE id=3")

    def test_empty_history_has_zero_reputation_and_cannot_prove(self):
        self.conn.execute('DELETE FROM reputation_records WHERE freelancer_id=3')
        self.conn.commit()
        row = self.conn.execute('SELECT * FROM users_with_reputation WHERE id=3').fetchone()
        self.assertEqual((row['completed_jobs'], row['rating_score'], row['on_time_rate']), (0, 0, 0))
        with self.assertRaisesRegex(ValueError, 'No completed'):
            generate_prover_toml(3, 1, os.path.join(self.temp.name, 'Prover.toml'))

    def test_prover_uses_stored_ratings(self):
        self.conn.execute('UPDATE reputation_records SET rating_scaled=425 WHERE freelancer_id=3')
        self.conn.commit()
        accept_edits(3)
        insert_test_credential(3)
        result = generate_prover_toml(3, 1, os.path.join(self.temp.name, 'Prover.toml'))
        inputs = result['private_inputs']
        self.assertEqual(inputs['ratings'], [425] * 40 + [0] * 24)
        self.assertEqual(sum(inputs['valid']), 40)
        self.assertEqual(sum(inputs['on_time']), 39)
        self.assertEqual(set(inputs), {'ratings', 'on_time', 'disputed', 'valid'})

    def test_web_reads_derived_history(self):
        import app
        with app.app.test_client() as client:
            with client.session_transaction() as session:
                session['user_id'] = 3
            self.assertEqual(client.get('/').status_code, 200)
            self.assertEqual(client.get('/database').status_code, 404)
            data = client.get('/api/check-eligibility/1').get_json()
            self.assertTrue(data['eligible'])
            self.assertEqual(data['freelancer_private_stats']['completed_jobs'], 40)
            self.conn.execute('UPDATE reputation_records SET on_time=0 WHERE freelancer_id=3')
            self.conn.commit()
            # Edited outside the app: refused until an admin accepts the change.
            response = client.get('/api/check-eligibility/1')
            self.assertEqual(response.status_code, 409)
            self.assertIn('signature check', response.get_json()['error'])
            accept_edits(3)
            self.assertFalse(client.get('/api/check-eligibility/1').get_json()['eligible'])

    def test_existing_database_preserved(self):
        source_path = os.path.join(os.path.dirname(database.__file__), 'freela.db')
        migrated_path = os.path.join(self.temp.name, 'existing.db')
        source = sqlite3.connect(source_path)
        record_count = source.execute('SELECT COUNT(*) FROM reputation_records').fetchone()[0]
        target = sqlite3.connect(migrated_path)
        source.backup(target)
        # Migrations add columns, so compare the columns that existed before.
        columns = {t: [r[1] for r in target.execute(f'PRAGMA table_info({t})')]
                   for t in ('users', 'jobs', 'applications')}
        before = {t: target.execute(f'SELECT {", ".join(columns[t])} FROM {t} ORDER BY id').fetchall()
                  for t in columns}
        source.close()
        target.close()
        source_key = os.path.join(os.path.dirname(database.__file__), '.local', 'signing_key.pem')
        if os.path.exists(source_key):
            import shutil
            temp_key = os.path.join(self.temp.name, '.local', 'signing_key.pem')
            os.makedirs(os.path.dirname(temp_key), exist_ok=True)
            shutil.copy2(source_key, temp_key)
            with integrity._key_lock:
                integrity._keys.pop(temp_key, None)
        with patch.object(database, 'DB_PATH', migrated_path):
            database.init_db()
            database.init_db()
            conn = database.get_db_connection()
            for table, rows in before.items():
                self.assertEqual([tuple(r) for r in conn.execute(
                    f'SELECT {", ".join(columns[table])} FROM {table} ORDER BY id')], rows)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM reputation_records').fetchone()[0], record_count)
            # Everything already stored was signed by the migration and checks out.
            self.assertEqual(integrity.audit(conn), [])
            conn.close()


if __name__ == '__main__':
    unittest.main()
