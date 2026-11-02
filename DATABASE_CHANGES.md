# Database milestone — 2 November 2026

Scope: a simple presentation demo, using the trusted database described in the midterm report. No Merkle tree, commitments, account-system redesign, or full marketplace lifecycle was added.

## Mistakes corrected

- User summary values had no job history behind them. Added `reputation_records` and the derived `users_with_reputation` view.
- The prover invented recent ratings on each call. It now reads stored records.
- SQLite foreign keys were declared but not enabled. Every application connection now enables them.
- The application duplicate check was not enforced by the database. Added a unique index on `(job_id, freelancer_id)`.
- Initialization had no versioned migration or rollback wrapper. Added a version marker and an atomic, repeatable migration.
- Static UI labels repeated unsupported old totals and claimed signed credentials. Updated the relevant labels and formatted derived values.

## History model

Each reputation row represents one completed, rated historical job. Fields: unique job reference, freelancer ID, client ID, rating scaled by 100, on-time flag, dispute flag, completion date, and demo-data flag. Historical references are separate from current marketplace listing IDs, so importing history does not create fake open listings. Freelancer and client IDs reference actual accounts.

For this milestone, all stored records count; there is no recent-history window. Each record has exactly one rating between 1.00 and 5.00. Unrated/in-progress jobs are outside this table. A dispute flag counts a job with a dispute once, rather than the number of dispute events. Empty history gives zero display totals and is ineligible for proof generation.

The database rejects duplicate references, out-of-range or fractional scaled ratings, invalid Boolean flags, invalid dates, missing accounts, and client/freelancer role mismatches. Referenced account roles cannot be changed in a way that invalidates history.

## Sample data

150 deterministic, explicitly marked demo records are seeded once. These are new presentation fixtures, not recovered real history or an invented reconstruction of the old summary totals.

| Freelancer | Completed jobs | Average rating | On time | Disputed jobs |
|---|---:|---:|---:|---:|
| alex_dev | 40 | 4.90 | 97.50% | 0 |
| sara_design | 30 | 4.80 | 93.33% | 1 |
| john_writer | 25 | 4.90 | 96.00% | 0 |
| data_guru | 35 | 4.80 | 91.43% | 1 |
| elena_ui | 20 | 4.95 | 100.00% | 0 |

Other accounts are not given invented histories. Deleting fixture records after migration does not silently reseed them at startup.

## Compatibility and remaining circuit work

Homepage, eligibility preview, database inspector, and prover read the derived view. The preview uses integer sums and cross multiplication. The old circuit still accepts aggregates, so its adapter supplies integer floors of the derived scaled average and on-time percentage, plus actual recent ratings (zero-padded only when necessary). This preserves threshold comparisons for integer-scaled requirements without rounding an applicant upward. The full history is available through `get_reputation_records` for the next circuit milestone.

Computing those aggregates **inside Noir from full record arrays remains unfinished**. This change does not claim to finish that part of the report or authenticate the database cryptographically. Threshold input validation, privacy/access controls, and proof-verification handling remain separate work.

## Preserved data and backup

The migration preserved all original columns and values in 7 users, 7 jobs, and 4 applications. Legacy user reputation columns remain for non-destructive compatibility, but application reputation reads no longer use them. Existing applications/proofs were preserved as historical demo artifacts; they were not regenerated against the new sample history.

The original SQLite database was backed up to `.local/backups/freela-before-reputation-v1.db` before migration. `.local/` and Python caches are ignored for new files; already tracked caches are not removed by this change.

## Files changed

- `database.py`: enforced foreign keys, migration, record schema, integrity constraints, view, fixtures, and history reader.
- `freela.db`: applied migration and added sample history; preserved existing accounts/listings/applications.
- `app.py`: switched reputation reads to the derived view and made eligibility checks use sums.
- `generate_prover.py`: removed synthesized ratings; reads history with a compatibility adapter for the existing circuit.
- `templates/base.html`, `templates/login.html`: removed hardcoded old reputation values.
- `templates/index.html`: replaced the signed-credential claim and formatted derived reputation.
- `templates/database_viewer.html`: identifies the derived view and formats its values.
- `.gitignore`: excludes local backups and newly created Python caches.
- `tests/test_database.py`: ten database/integration tests.
- `DATABASE_CHANGES.md`: this complete change record.

## Verification

`python -B -m unittest discover -s tests -v`: ten tests passed, covering initialization, repeatability, migration preservation, database integrity, foreign keys, duplicates, invalid records, role changes, derived totals, empty history, prover input sourcing, and web reads. Checks ran against temporary databases. The actual migrated database also passed integrity and foreign-key checks, with original rows compared before and after migration. No real Noir/Barretenberg proof was generated in this milestone.
