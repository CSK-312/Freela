"""Server signatures over reviews, reputation history and credentials.

The Ed25519 signing key is a file in .local/ beside the database and never inside it, so
someone who can only edit freela.db cannot change, add, reorder or delete signed rows
without the checks below noticing. Each freelancer's history is also a hash chain, so
dropping a record breaks every later link, and each credential signs the chain head it
committed to, so cutting records off the end is caught as well.

Limits: whoever holds the key file (i.e. the server itself) can still sign anything, and
rolling the database back to an older, fully consistent copy is not detectable.
"""
import hashlib
import json
import os
import sys
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import database

GENESIS = '0' * 64

_keys = {}
_key_lock = threading.Lock()


class TamperError(ValueError):
    """Stored data does not match its signature."""


def key_path():
    return os.path.join(os.path.dirname(database.DB_PATH), '.local', 'signing_key.pem')


def _signing_key(create=False):
    """Load the key once per path. Only the migration may create it; afterwards a missing key is an error."""
    path = key_path()
    with _key_lock:
        if path in _keys:
            return _keys[path]
        try:
            with open(path, 'rb') as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
        except FileNotFoundError:
            if not create:
                raise RuntimeError(f'Signing key {path} is missing, so stored signatures cannot be checked.')
            key = Ed25519PrivateKey.generate()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as f:
                f.write(pem)
        _keys[path] = key
        return key


def public_key_fingerprint():
    raw = _signing_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _sign(payload):
    return _signing_key().sign(_canonical(payload)).hex()


def _valid(payload, signature):
    try:
        _signing_key().public_key().verify(bytes.fromhex(signature or ''), _canonical(payload))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---- Reviews -------------------------------------------------------------------------

def _review_payload(review):
    return {'type': 'review/v1', 'job_id': review['job_id'], 'reviewer_id': review['reviewer_id'],
            'reviewee_id': review['reviewee_id'], 'rating_scaled': review['rating_scaled'],
            'comment': review['comment'], 'disputed': review['disputed'], 'created_at': review['created_at']}


def add_review(conn, job_id, reviewer_id, reviewee_id, rating_scaled, comment, disputed=0):
    created_at = conn.execute('SELECT CURRENT_TIMESTAMP').fetchone()[0]
    review = {'job_id': job_id, 'reviewer_id': reviewer_id, 'reviewee_id': reviewee_id,
              'rating_scaled': rating_scaled, 'comment': comment, 'disputed': disputed, 'created_at': created_at}
    conn.execute('''INSERT INTO reviews (job_id, reviewer_id, reviewee_id, rating_scaled, comment, disputed,
        created_at, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                 (*review.values(), _sign(_review_payload(review))))


def review_is_authentic(review):
    return _valid(_review_payload(review), review['signature'])


def client_ratings(conn, client_ids):
    """{client_id: {'client_rating', 'client_review_count'}} from signature-checked reviews only."""
    client_ids = list(set(client_ids))
    ratings = {client_id: {'client_rating': None, 'client_review_count': 0} for client_id in client_ids}
    if not client_ids:
        return ratings
    reviews = conn.execute('SELECT * FROM reviews WHERE reviewee_id IN (' + ','.join('?' * len(client_ids)) + ')',
                           client_ids).fetchall()
    for client_id in client_ids:
        scores = [r['rating_scaled'] for r in reviews if r['reviewee_id'] == client_id and review_is_authentic(r)]
        if scores:
            ratings[client_id] = {'client_rating': sum(scores) / len(scores) / 100, 'client_review_count': len(scores)}
    return ratings


# ---- Reputation history (hash chain per freelancer) -----------------------------------

def _record_payload(record):
    return {'type': 'reputation_record/v1', 'job_reference': record['job_reference'],
            'freelancer_id': record['freelancer_id'], 'client_id': record['client_id'],
            'rating_scaled': record['rating_scaled'], 'on_time': record['on_time'],
            'disputed': record['disputed'], 'completed_at': record['completed_at'], 'is_demo': record['is_demo']}


def _link(previous_hash, record):
    return hashlib.sha256(previous_hash.encode('ascii') + _canonical(_record_payload(record))).hexdigest()


def _link_payload(freelancer_id, index, chain_hash):
    return {'type': 'reputation_link/v1', 'freelancer_id': freelancer_id, 'chain_index': index, 'chain_hash': chain_hash}


def append_reputation_record(conn, job_reference, freelancer_id, client_id, rating_scaled, on_time, disputed,
                             completed_at, is_demo=0):
    """Add a record to the end of the freelancer's chain. Call inside a write transaction."""
    head = conn.execute('''SELECT chain_index, chain_hash FROM reputation_records WHERE freelancer_id = ?
        ORDER BY chain_index DESC LIMIT 1''', (freelancer_id,)).fetchone()
    index, previous = (head[0] + 1, head[1]) if head else (1, GENESIS)
    record = {'job_reference': job_reference, 'freelancer_id': freelancer_id, 'client_id': client_id,
              'rating_scaled': rating_scaled, 'on_time': int(on_time), 'disputed': int(disputed),
              'completed_at': completed_at, 'is_demo': is_demo}
    chain_hash = _link(previous, record)
    conn.execute('''INSERT INTO reputation_records (job_reference, freelancer_id, client_id, rating_scaled, on_time,
        disputed, completed_at, is_demo, chain_index, chain_hash, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (*record.values(), index, chain_hash, _sign(_link_payload(freelancer_id, index, chain_hash))))


def resign_history(conn, freelancer_id):
    """Rebuild and sign a freelancer's chain over the rows as stored now, in proving order.

    Used once by the migration, and by an admin to accept a deliberate correction.
    """
    previous = GENESIS
    rows = conn.execute('''SELECT * FROM reputation_records WHERE freelancer_id = ?
        ORDER BY completed_at, id''', (freelancer_id,)).fetchall()
    # Clear first so renumbering never collides with the unique (freelancer, index) pair.
    conn.execute('UPDATE reputation_records SET chain_index = NULL WHERE freelancer_id = ?', (freelancer_id,))
    for index, row in enumerate(rows, start=1):
        previous = _link(previous, row)
        conn.execute('UPDATE reputation_records SET chain_index = ?, chain_hash = ?, signature = ? WHERE id = ?',
                     (index, previous, _sign(_link_payload(freelancer_id, index, previous)), row['id']))
    return previous


def accept_corrected_history(conn, freelancer_id):
    """Admin action: sign the history as stored now and revoke credentials over the old version."""
    resign_history(conn, freelancer_id)
    conn.execute('UPDATE credentials SET revoked_at = CURRENT_TIMESTAMP WHERE freelancer_id = ? AND revoked_at IS NULL',
                 (freelancer_id,))


def verified_history(conn, freelancer_id):
    """The freelancer's full history in chain order, or TamperError if any link fails."""
    rows = conn.execute('''SELECT * FROM reputation_records WHERE freelancer_id = ?
        ORDER BY chain_index, id''', (freelancer_id,)).fetchall()
    previous = GENESIS
    for index, row in enumerate(rows, start=1):
        label = f"Job history record {row['job_reference']}"
        if row['chain_index'] != index:
            raise TamperError(f'{label} is out of sequence: a record was removed, added or reordered.')
        previous = _link(previous, row)
        if previous != row['chain_hash']:
            raise TamperError(f'{label} was changed after it was signed (or an earlier record was).')
        if not _valid(_link_payload(freelancer_id, index, previous), row['signature']):
            raise TamperError(f'{label} has an invalid signature.')
    return rows


def reputation_summary(records):
    """The same figures users_with_reputation derives in SQL, from already-verified records."""
    count = len(records)
    rating_sum = sum(r['rating_scaled'] for r in records)
    on_time = sum(r['on_time'] for r in records)
    return {
        'completed_jobs': count, 'rating_sum': rating_sum, 'on_time_count': on_time,
        'dispute_count': sum(r['disputed'] for r in records),
        'rating_score': rating_sum / (100 * count) if count else 0,
        'on_time_rate': 100 * on_time / count if count else 0,
        'rating_scaled_floor': rating_sum // count if count else 0,
        'on_time_rate_floor': 100 * on_time // count if count else 0,
    }


def verified_reputation(conn, freelancer_id):
    """Summary of the signature-checked history, with integrity_error set (and no figures) if it fails."""
    try:
        return {**reputation_summary(verified_history(conn, freelancer_id)), 'integrity_error': None}
    except TamperError as e:
        return {'integrity_error': str(e)}


# ---- Credentials ---------------------------------------------------------------------

def _credential_payload(credential):
    return {'type': 'credential/v1', 'freelancer_id': credential['freelancer_id'], 'version': credential['version'],
            'commitment': credential['commitment'], 'record_count': credential['record_count'],
            'history_hash': credential['history_hash']}


def store_credential(conn, freelancer_id, commitment, salt, history):
    """Sign and insert the next credential version over `history` (verified records). Call inside a write transaction."""
    version = conn.execute('SELECT COALESCE(MAX(version), 0) + 1 FROM credentials WHERE freelancer_id = ?',
                           (freelancer_id,)).fetchone()[0]
    credential = {'freelancer_id': freelancer_id, 'version': version, 'commitment': commitment,
                  'record_count': len(history), 'history_hash': history[-1]['chain_hash']}
    cursor = conn.execute('''INSERT INTO credentials (freelancer_id, version, commitment, salt, record_count,
        history_hash, signature) VALUES (?, ?, ?, ?, ?, ?, ?)''',
                          (freelancer_id, version, commitment, salt, credential['record_count'],
                           credential['history_hash'], _sign(_credential_payload(credential))))
    return {**credential, 'id': cursor.lastrowid}


def sign_existing_rows(conn):
    """Migration only: sign everything stored before signatures existed (trust on first use)."""
    _signing_key(create=True)
    for (freelancer_id,) in conn.execute('SELECT DISTINCT freelancer_id FROM reputation_records').fetchall():
        resign_history(conn, freelancer_id)
    for review in conn.execute('SELECT * FROM reviews').fetchall():
        conn.execute('UPDATE reviews SET signature = ? WHERE id = ?', (_sign(_review_payload(review)), review['id']))
    for credential in conn.execute('SELECT * FROM credentials').fetchall():
        head = conn.execute('SELECT chain_hash FROM reputation_records WHERE freelancer_id = ? AND chain_index = ?',
                            (credential['freelancer_id'], credential['record_count'])).fetchone()
        if head is None:
            # Its records are gone, so it could never be used again; a new one is issued on the next application.
            conn.execute('UPDATE credentials SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE id = ?',
                         (credential['id'],))
            continue
        signed = {**dict(credential), 'history_hash': head[0]}
        conn.execute('UPDATE credentials SET history_hash = ?, signature = ? WHERE id = ?',
                     (head[0], _sign(_credential_payload(signed)), credential['id']))


def check_credential(credential, history):
    """The credential is genuine and the history it committed to is still the start of `history`."""
    if not _valid(_credential_payload(credential), credential['signature']):
        raise TamperError(f"Credential v{credential['version']} has an invalid signature.")
    count = credential['record_count']
    if count > len(history) or history[count - 1]['chain_hash'] != credential['history_hash']:
        raise TamperError(f"Credential v{credential['version']} covered {count} jobs that are no longer all in the history.")


# ---- Audit ---------------------------------------------------------------------------

def audit(conn):
    """Every integrity problem in the database, for the admin page and the CLI."""
    problems = []
    for freelancer in conn.execute("SELECT id, username FROM users WHERE role = 'freelancer' ORDER BY id"):
        try:
            history = verified_history(conn, freelancer['id'])
            credential = database.get_current_credential(conn, freelancer['id'])
            if credential is not None:
                check_credential(credential, history)
        except TamperError as e:
            problems.append({'area': 'History', 'subject': freelancer['username'], 'problem': str(e)})
    for review in conn.execute('''SELECT r.*, a.username AS reviewer, b.username AS reviewee FROM reviews r
            JOIN users a ON a.id = r.reviewer_id JOIN users b ON b.id = r.reviewee_id ORDER BY r.id'''):
        if not review_is_authentic(review):
            problems.append({'area': 'Review', 'subject': f"job #{review['job_id']}: {review['reviewer']} → {review['reviewee']}",
                             'problem': 'Signature does not match the stored review; it is excluded from ratings.'})
    return problems


if __name__ == '__main__':
    connection = database.get_db_connection()
    try:
        if sys.argv[1:2] == ['resign'] and len(sys.argv) == 3:
            # Accept the stored history as correct after a deliberate fix; the next application issues a credential.
            connection.execute('BEGIN IMMEDIATE')
            accept_corrected_history(connection, int(sys.argv[2]))
            connection.commit()
            print(f'Re-signed history of freelancer {sys.argv[2]} and revoked their credentials; the next application issues a new one.')
        elif sys.argv[1:] in ([], ['audit']):
            found = audit(connection)
            print(f'Signing key {public_key_fingerprint()}: ' + ('no problems found.' if not found else f'{len(found)} problem(s):'))
            for item in found:
                print(f"  [{item['area']}] {item['subject']}: {item['problem']}")
            sys.exit(1 if found else 0)
        else:
            print('Usage: python integrity.py [audit | resign <freelancer_id>]')
            sys.exit(2)
    finally:
        connection.close()
