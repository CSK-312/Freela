# Freela code review

Reviewed 28 October 2026, commit b2e08edf4d05e467afe5623acc28770bf4e02db9.

## Assessment

This is a Flask/SQLite classroom-style marketplace prototype with a Noir/Barretenberg proof pipeline. It has browsing, search, category filtering, demo accounts, job creation, eligibility previews, and applications. It is not ready for real users. The central gap is that the proof checks eligibility numbers without authenticating their source. Privacy and access controls also need correction.

All five Python source files, five templates, CSS, Noir source/configuration, prover inputs, repository contents, and database schema were reviewed. Python syntax and isolated Flask request checks ran locally. The original database was inspected read-only and passed SQLite integrity checking (7 users, 7 jobs, 4 applications). Application source and original database were not changed.

## Priority findings

1. **Critical outside an explicitly isolated demo: account impersonation.** `app.py:16` automatically logs anonymous visitors in as user 3. `app.py:117` switches to any existing account without credentials. Logout redirects to a page that immediately logs the visitor back in. These behaviors were reproduced. Remove them from normal operation; require authenticated sessions and enforce ownership/roles on the server. If retained for a demonstration, put them behind an explicit demo configuration.

2. **Critical: exposed session secret and unsafe deployment settings.** `app.py:8` commits the session-signing secret, allowing someone who knows it to construct trusted session data. `app.py:312` enables debug mode and listens on all interfaces. Passwords use unsalted SHA-256 and seeded accounts share a published password. Replace the secret, load it from deployment configuration, use a password-specific hash, and use a production server with debug disabled. Add CSRF protection and login throttling; use POST for logout and other state changes.

3. **High: private reputation is publicly accessible.** `/database` has no access restriction and displays everyone's reputation (`app.py:287`, `templates/database_viewer.html:55`). An anonymous request returned 200. Switching accounts also exposes their stats through the eligibility API. The repository contains the database, plaintext `Prover.toml`, and a witness file. Restrict/remove the inspector and keep generated private inputs out of source control. Showing a user's own stats to that authenticated user is reasonable; exposing every user's stats is not. The server currently sees all private inputs, so privacy claims must state that trust boundary.

4. **High: the proof does not authenticate reputation.** `circuit/src/main.nr:4` only compares supplied values to thresholds. No issuer signature, trusted commitment/root, credential validity, applicant binding, or job-specific challenge is checked. `generate_prover.py:35` invents recent ratings; the circuit merely checks their bounds and positive sum, without linking them to the aggregate rating. This proves that a satisfying set of numbers exists, not that the applicant earned those numbers. The current server supplies DB values, so this is a trust-model gap rather than evidence that the HTTP route accepts arbitrary client proofs. Add trusted credential issuance and in-circuit authentication, bind the proof to the applicant and job, and define expiry/revocation/replay handling. Remove the UI's “Signed Credential” claim until implemented.

5. **High: failed proofs are saved and shown as verified.** `app.py:258` inserts an application even when verification returns false; `templates/index.html:268` always renders “ZK Proof Verified.” Confirmed with a mocked verifier failure. Reject failed verification before insertion, and render the actual stored status. Also treat verifier process errors separately from eligibility failure.

6. **High: concurrent proof requests share mutable files.** `zk_engine.py:34` onward overwrites the same circuit, prover inputs, witness, proof, public inputs, and verification key for every request. Requests can interfere, and saved metadata can become associated with another request's artifacts. Give each proof task an isolated directory, use a trusted/versioned circuit and verification key, and compare verified public inputs with the intended job criteria. Keep necessary verification artifacts for later independent checking; currently the DB stores proof hex and JSON thresholds while keys/artifacts are overwritten.

7. **High: validation and application lifecycle checks are missing.** Malformed budget, bid, and missing password produced HTTP 500. A negative budget, invalid category, and 150% on-time threshold were accepted. Applying to a completed job was also accepted with a mocked successful proof. Validate required fields, lengths, finite numeric values, ranges, category membership, job existence/status, and user role before launching expensive proof work. Use a consistent fixed-point rating representation; preview conversion truncates while prover conversion rounds.

8. **Medium: weak database integrity under concurrent use.** `database.py:6` does not enable SQLite foreign keys (confirmed disabled). Applications lack a unique `(job_id, freelancer_id)` constraint; a check-before-insert alone cannot prevent concurrent duplicates. Add foreign-key enforcement, uniqueness, domain checks, migrations, useful indexes, and reliable connection cleanup. Represent money in integer minor units or a deliberate decimal model.

9. **Medium: proof execution is not reproducible or operationally robust.** The configured Nargo and Barretenberg executables do not exist on this machine. The tracked virtual environment refers to Linux paths and is not a portable Windows environment. There is no Python dependency manifest, setup guide, pinned toolchain, or CI. The committed circuit artifact reports Noir `1.0.0-beta.26+40d6574f851d926f93e0c3a271bac3e6e82ac905`, but that does not establish a compatible installed Barretenberg version. Subprocesses have no timeouts and proof work blocks the request. Document a supported environment, pin compatible versions, add startup checks, bounded background workers, cleanup, and diagnostics. Do not infer proof validity from the existence of committed output files.

10. **Medium: generator options are inconsistent.** `generate_circuit.py:70` always generates a five-element test array even when `num_past_jobs` differs. `min_rating_scale` changes a comment but the rating bound remains 500. The prover also clamps recent ratings to 100–500 regardless of scale. Either support these parameters consistently or remove them. Test non-default sizes, boundaries, and invalid credentials.

## Product work still needed

- Real registration, account/profile management, recovery, and authenticated role-based dashboards.
- A client view of applications to their jobs, shortlist/accept/reject actions, and a job/contract lifecycle through completion.
- Real completed-job/review records and a defined reputation issuer; fabricated history cannot support the intended credential claims.
- A job detail view showing the description and delivery expectations. The application modal currently hardcodes “3 days”; job creation has no delivery-days input, so it defaults to seven.
- Honest proof progress and error states. Remove unused random simulated proof fields (the backend ignores them), prevent duplicate submissions, and distinguish network/tool failures from ineligibility. Guard against stale eligibility responses when switching jobs quickly.
- Empty results, pagination, mobile navigation, keyboard/focus handling for the modal, and accessible form labels. Visual layout was reviewed in source, not validated in a browser.
- For a commercial marketplace, define payments, contracts, disputes, messaging, and notifications. These are scope decisions, not prerequisites for a classroom eligibility demonstration.

## Recommended order

1. Make setup reproducible; document the demo scope and tool versions. Add `.gitignore`; remove runtime environments, caches, private inputs, DB state, and build outputs from tracking after preserving any needed sample data separately.
2. Fix authentication, privacy leaks, false verification labels, validation, and database constraints.
3. Implement the credential trust model, isolated proof execution, explicit public-input binding, and durable verification records.
4. Add tests for unauthorized access, failed/tampered proofs, boundary values, concurrent applications, closed jobs, and credential replay. Run actual Noir tests and a real end-to-end proof with the pinned toolchain.
5. Complete client hiring and job lifecycle flows, then improve mobile/accessibility and deployment operations.

## Verification limits

HTTP checks used a newly seeded temporary database. Proof-failure and closed-job tests mocked the engine to isolate web application behavior. No real cryptographic proof was generated or independently verified because the configured tools are absent. Concurrency risks and generator parameter issues are source-review findings, not reproduced concurrent/compiler failures. No production deployment or browser visual test was performed.
