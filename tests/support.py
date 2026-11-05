"""Shared test helpers."""
import database
import integrity


def insert_test_credential(freelancer_id):
    """A stand-in credential over the freelancer's current history (no toolchain needed).

    Its commitment is not a real hash, so it only suits tests that never run the circuit.
    It is signed like a real one, so the prover's credential check accepts it.
    """
    conn = database.get_db_connection()
    try:
        conn.execute('BEGIN IMMEDIATE')
        history = integrity.verified_history(conn, freelancer_id)
        integrity.store_credential(conn, freelancer_id, '0x' + '1' * 64, '0x' + '2' * 64, history)
        conn.commit()
    finally:
        conn.close()


def accept_edits(freelancer_id):
    """Accept directly edited history as correct, as the admin correction command does."""
    conn = database.get_db_connection()
    try:
        integrity.accept_corrected_history(conn, freelancer_id)
        conn.commit()
    finally:
        conn.close()
