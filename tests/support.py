"""Shared test helpers."""
import database


def insert_test_credential(freelancer_id):
    """A stand-in credential over the freelancer's current history (no toolchain needed).

    Its commitment is not a real hash, so it only suits tests that never run the circuit.
    """
    conn = database.get_db_connection()
    try:
        count = conn.execute('SELECT COUNT(*) FROM reputation_records WHERE freelancer_id = ?',
                             (freelancer_id,)).fetchone()[0]
        version = conn.execute('SELECT COALESCE(MAX(version), 0) + 1 FROM credentials WHERE freelancer_id = ?',
                               (freelancer_id,)).fetchone()[0]
        conn.execute('''INSERT INTO credentials (freelancer_id, version, commitment, salt, record_count)
            VALUES (?, ?, ?, ?, ?)''', (freelancer_id, version, '0x' + '1' * 64, '0x' + '2' * 64, count))
        conn.commit()
    finally:
        conn.close()
