"""Build private full-history arrays and public requirements from the trusted DB."""
from decimal import Decimal
from pathlib import Path
import sys

from database import get_db_connection, get_current_credential
from generate_circuit import DEFAULT_HISTORY_CAPACITY, validate_capacity
import integrity

# BN254 scalar field order; Noir Field values must be below it.
FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def field_hex(value):
    if not 0 <= value < FIELD_MODULUS:
        raise ValueError('Value is not a field element.')
    return '0x' + format(value, '064x')


def history_arrays(records, num_past_jobs):
    """The padded witness arrays shared by credential issuance and proving."""
    if not records:
        raise ValueError('No completed, rated job history is available.')
    if len(records) > num_past_jobs:
        raise ValueError(f'Full history has {len(records)} jobs; circuit capacity is {num_past_jobs}. Increase capacity; no records were truncated.')
    padding = [0] * (num_past_jobs - len(records))
    return {
        'ratings': [r['rating_scaled'] for r in records] + padding,
        'on_time': [r['on_time'] for r in records] + padding,
        'disputed': [r['disputed'] for r in records] + padding,
        'valid': [1] * len(records) + padding,
    }


def _write_toml(path, comment, arrays, scalars):
    lines = ['# ' + comment]
    for key, values in arrays.items():
        lines.append(key + ' = [' + ', '.join('"' + str(v) + '"' for v in values) + ']')
    for key, value in scalars.items():
        lines.append(key + ' = "' + str(value) + '"')
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def _read_snapshot(freelancer_id, job_id=None):
    conn = get_db_connection()
    try:
        # Read identity, requirements, credential and ALL history from one database snapshot.
        conn.execute('BEGIN')
        freelancer = conn.execute('SELECT * FROM users WHERE id=?', (freelancer_id,)).fetchone()
        job = conn.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone() if job_id is not None else None
        if not freelancer or freelancer['role'] != 'freelancer':
            raise ValueError('Reputation owner must be an existing freelancer.')
        # Every record's signature and chain link, and the current credential's signature
        # over the history it covered, are checked before anything reaches a circuit.
        records = integrity.verified_history(conn, freelancer_id)
        credential = get_current_credential(conn, freelancer_id)
        if credential is not None:
            integrity.check_credential(credential, records)
    finally:
        conn.close()
    return freelancer, job, records, credential


def generate_commit_toml(freelancer_id, salt, output_path, num_past_jobs=DEFAULT_HISTORY_CAPACITY):
    """Inputs for the issuer's commitment circuit over the freelancer's full current history."""
    validate_capacity(num_past_jobs)
    _, _, records, _ = _read_snapshot(freelancer_id)
    arrays = history_arrays(records, num_past_jobs)
    _write_toml(output_path, 'Credential issuance: full stored job history.', arrays,
                {'applicant_id': freelancer_id, 'salt': salt})
    return {'record_count': len(records), 'history': records}


def generate_prover_toml(freelancer_id, job_id, output_path=None,
                         num_past_jobs=DEFAULT_HISTORY_CAPACITY, rating_scale=100):
    validate_capacity(num_past_jobs)
    if rating_scale != 100:
        raise ValueError('The database stores ratings at scale 100.')
    freelancer, job, records, credential = _read_snapshot(freelancer_id, job_id)
    if not job:
        raise ValueError('Job not found.')
    private_inputs = history_arrays(records, num_past_jobs)
    if credential is None:
        raise ValueError('No credential has been issued for this freelancer yet.')
    if credential['record_count'] != len(records):
        raise ValueError(f"Your credential covers {credential['record_count']} jobs but your history has {len(records)}. "
                         'It must be reissued before you can prove eligibility.')

    scaled = Decimal(str(job['min_rating'])) * 100
    if not scaled.is_finite() or scaled != scaled.to_integral_value() or not 100 <= scaled <= 500:
        raise ValueError('Minimum rating must be between 1 and 5 with at most two decimal places.')
    thresholds = {
        'min_rating_scaled': int(scaled),
        'min_completed_jobs': job['min_completed_jobs'],
        'min_on_time_rate': job['min_on_time_rate'],
        'max_disputes': job['max_disputes'],
    }
    for value in thresholds.values():
        if type(value) is not int or not 0 <= value <= 2**32 - 1:
            raise ValueError('Public thresholds must be non-negative u32 integers.')
    if thresholds['min_on_time_rate'] > 100:
        raise ValueError('Minimum on-time percentage must be at most 100.')
    # Order matches the circuit's public parameters, which is the order the verifier sees.
    public_inputs = {**thresholds, 'job_id': job['id'], 'applicant_id': freelancer['id'],
                     'commitment': credential['commitment']}

    # Never supply claimed aggregate metrics as witness inputs.
    path = Path(output_path) if output_path else Path(__file__).parent / 'circuit/Prover.toml'
    _write_toml(path, 'Full stored job history; private arrays, public job requirements.',
                private_inputs, {'salt': credential['salt'], **public_inputs})
    return {
        'output_path': str(path),
        'freelancer_username': freelancer['username'],
        'job_title': job['title'],
        'credential_id': credential['id'],
        'credential_version': credential['version'],
        'private_inputs': private_inputs,
        'public_inputs': public_inputs,
    }


if __name__ == '__main__':
    result = generate_prover_toml(int(sys.argv[1]) if len(sys.argv) > 1 else 3,
                                  int(sys.argv[2]) if len(sys.argv) > 2 else 1)
    print('Generated full-history inputs:', result['output_path'])
