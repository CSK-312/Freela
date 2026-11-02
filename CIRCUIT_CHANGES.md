# Full-history Noir circuit — 2 November 2026

This implements the report's trusted-database milestone: loop over private job arrays, calculate reputation within Noir, and check all four public thresholds using integer arithmetic. No Merkle trees, commitments, signatures, or extra marketplace features were added.

## Changes in this milestone

1. `generate_circuit.py` and generated `circuit/src/main.nr`: removed claimed aggregate witness inputs. Added aligned private arrays `ratings`, `on_time`, `disputed`, and `valid`. Each valid index represents one completed, rated job from the database. Noir computes job count, rating sum, on-time count, and dispute count itself.
2. The circuit checks `jobs >= min_completed_jobs`, `rating_sum >= min_rating_scaled * jobs`, `100 * on_time_count >= min_on_time_rate * jobs`, and `dispute_count <= max_disputes`. There is no division, rounded average, or public disclosure of computed metrics.
3. Validated ratings (100–500), Boolean flags (0/1), public rating/percentage bounds, nonempty history, and zero padding. Sums and products use u64; the supported capacity range of 2–4096 and u32 public thresholds keep products within u64.
4. `generate_prover.py`: reads every stored record in one database snapshot, writes the four arrays, and never sends aggregate scores as witness inputs. Public ratings must be exactly representable at scale 100. Invalid thresholds are rejected before invoking the compiler.
5. The default padded capacity is 64, enough for every current demo account. `num_past_jobs` now means capacity, not a recent-history window. A larger history is rejected with an explicit message; it is never truncated. Change capacity consistently via the engine argument when needed. Padding keeps circuit shape independent of the actual number of records within that capacity.
6. `zk_engine.py`: uses the same capacity for source and witness generation, validates inputs first, and always recompiles so the old committed aggregate-circuit artifact cannot be reused by this path.
7. `circuit/Prover.toml`: regenerated the example for Alex applying to job 1, using all 40 stored records and 24 zero-padding slots.
8. `app.py` and `templates/index.html`: labelled the existing UI summary as a preview rather than claiming it is the circuit witness. Renamed its JSON field to `preview_stats`. The UI explains that the actual witness is built from full records on submission.
9. Tests: updated database/prover assertions, added full-history mapping/capacity/validation/orchestration tests, and embedded 14 Noir tests covering exact thresholds, each failed criterion, padding, empty history, and malformed inputs. Added an optional real Nargo integration test that runs Noir tests, executes an eligible database witness, and checks rejection after the oldest record worsens.

## Verification and limits

Verified on 2 November 2026 with Nargo `1.0.0-beta.26` and Barretenberg `5.2.0` in Ubuntu/WSL:

- All 14 embedded Noir tests passed.
- The circuit compiled to ACIR.
- The database-generated witness solved successfully.
- Barretenberg generated a 14,656-byte UltraHonk proof.
- A separate `bb verify` invocation returned `Proof verified successfully`.
- The full Windows Python `zk_engine.py` path also generated and verified the proof through WSL after cross-platform path handling was fixed.

Existing database applications were not re-proved. The installed binaries live in the current machine's Ubuntu user profile and are not part of the repository.

As proposed, the backend is trusted to supply the complete, correct history. This circuit verifies the computations over those records; it does not authenticate their origin or prevent a malicious trusted backend from fabricating/omitting records. Those are the later authenticated-state extensions in the report.

Syntax references checked: [Noir arrays](https://noir-lang.org/docs/noir/concepts/data_types/arrays) and [Noir tests](https://noir-lang.org/docs/tooling/tests). These do not substitute for execution with the project's toolchain.
