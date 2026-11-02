"""Build private full-history arrays and public requirements from the trusted DB."""
from decimal import Decimal
from pathlib import Path
import sys

from database import get_db_connection, get_reputation_records
from generate_circuit import DEFAULT_HISTORY_CAPACITY, validate_capacity


def generate_prover_toml(freelancer_id, job_id, output_path=None,
                         num_past_jobs=DEFAULT_HISTORY_CAPACITY, rating_scale=100):
    validate_capacity(num_past_jobs)
    if rating_scale != 100:
        raise ValueError('The database stores ratings at scale 100.')
    conn = get_db_connection()
    try:
        # Read identity, requirements and ALL history from one database snapshot.
        conn.execute('BEGIN')
        freelancer = conn.execute('SELECT * FROM users WHERE id=?', (freelancer_id,)).fetchone()
        job = conn.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
        records = get_reputation_records(conn, freelancer_id)
    finally:
        conn.close()
    if not freelancer or freelancer['role'] != 'freelancer':
        raise ValueError('Reputation owner must be an existing freelancer.')
    if not job:
        raise ValueError('Job not found.')
    if not records:
        raise ValueError('No completed, rated job history is available.')
    if len(records) > num_past_jobs:
        raise ValueError(f'Full history has {len(records)} jobs; circuit capacity is {num_past_jobs}. Increase capacity; no records were truncated.')

    scaled = Decimal(str(job['min_rating'])) * 100
    if not scaled.is_finite() or scaled != scaled.to_integral_value() or not 100 <= scaled <= 500:
        raise ValueError('Minimum rating must be between 1 and 5 with at most two decimal places.')
    public_inputs = {
        'min_rating_scaled': int(scaled),
        'min_completed_jobs': job['min_completed_jobs'],
        'min_on_time_rate': job['min_on_time_rate'],
        'max_disputes': job['max_disputes'],
    }
    for value in public_inputs.values():
        if type(value) is not int or not 0 <= value <= 2**32 - 1:
            raise ValueError('Public thresholds must be non-negative u32 integers.')
    if public_inputs['min_on_time_rate'] > 100:
        raise ValueError('Minimum on-time percentage must be at most 100.')

    padding = [0] * (num_past_jobs - len(records))
    private_inputs = {
        'ratings': [r['rating_scaled'] for r in records] + padding,
        'on_time': [r['on_time'] for r in records] + padding,
        'disputed': [r['disputed'] for r in records] + padding,
        'valid': [1] * len(records) + padding,
    }
    # Never supply claimed aggregate metrics as witness inputs.
    lines = ['# Full stored job history; private arrays, public job requirements.']
    for key, values in private_inputs.items():
        lines.append(key + ' = [' + ', '.join('"' + str(v) + '"' for v in values) + ']')
    for key, value in public_inputs.items():
        lines.append(key + ' = "' + str(value) + '"')
    path = Path(output_path) if output_path else Path(__file__).parent / 'circuit/Prover.toml'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return {
        'output_path': str(path),
        'freelancer_username': freelancer['username'],
        'job_title': job['title'],
        'private_inputs': private_inputs,
        'public_inputs': public_inputs,
    }


if __name__ == '__main__':
    result = generate_prover_toml(int(sys.argv[1]) if len(sys.argv) > 1 else 3,
                                  int(sys.argv[2]) if len(sys.argv) > 2 else 1)
    print('Generated full-history inputs:', result['output_path'])
