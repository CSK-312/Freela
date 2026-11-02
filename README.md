# Freela

A prototype freelance marketplace where freelancers prove they qualify for a job **without revealing their track record**. Clients set public requirements (minimum rating, completed jobs, on-time rate, maximum disputes); freelancers apply with a zero-knowledge proof built in [Noir](https://noir-lang.org) and verified with Barretenberg (UltraHonk). Clients see only that the proof passed.

College project for CS670, Applied Cryptography & Zero-Knowledge Systems. Payments, messaging and notifications are out of scope.

## Features

- **Accounts:** username and password sign-up as a client or a freelancer; salted password hashes; every page requires login and the right role.
- **Clients:** post jobs with ZK requirements; review applicants (proof status, bid, cover note — never their stats); hire one; approve delivered work and rate it.
- **Freelancers:** browse jobs, see live eligibility, apply with a real proof, mark work delivered, rate the client; a private dashboard of their own reputation.
- **Feedback loop:** every approved job becomes part of the freelancer's private history (on-time is computed from the delivery date), and their credential is reissued so the next proof covers it.

## How the zero-knowledge part works

1. **Credential.** The platform keeps each freelancer's full job history. When a job is reviewed, it computes a Pedersen commitment over that history, the freelancer's account id and a random secret salt (`circuit_commit/`), and stores it as the freelancer's current credential.
2. **Proof.** To apply, the eligibility circuit (`circuit/`) takes the history and salt as private inputs. Public inputs are the job's four thresholds, the job id, the applicant id and the commitment. The circuit checks the history matches the commitment, then derives the totals itself and checks every threshold. No averages or totals are ever supplied as inputs.
3. **Verification.** The server verifies the proof against a verification key pinned at startup, and only accepts it if its public inputs are exactly this job, this applicant and their current commitment. Each application stores the credential version and key hash it was checked against.

**What this guarantees:** clients never learn a freelancer's numbers; history edited or dropped after issuance can't produce a valid proof; a proof can't be reused for another job or person.
**Trust model:** the platform is the credential issuer, so it holds the history and salt and runs the prover. The zero knowledge is toward clients, not the platform.

## Setup

Requires Python 3.9+ and, for proofs, the pinned Noir toolchain (Nargo `1.0.0-beta.26`, Barretenberg `5.2.0`). macOS and Linux run it natively; on Windows the app uses the toolchain inside WSL. See [TOOLCHAIN.md](TOOLCHAIN.md) for install commands.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
```

Open http://localhost:5001 (port 5000 is taken by AirPlay on macOS). The database `freela.db` is created and seeded on first start; delete it to start fresh. The first application after a restart takes a few extra seconds while the circuits compile.

Optional settings (environment variables): `FREELA_SECRET_KEY` (otherwise one is generated into `.local/`), `FREELA_PORT`, `FREELA_DEBUG=1`, `NARGO_BIN` / `BB_BIN` (tool paths), `FREELA_WSL_DISTRO`.

## Demo

All seeded accounts use the password `password123`.

| Account | Role | Notes |
|---|---|---|
| `client_alice`, `client_techcorp` | Client | Own the seeded jobs |
| `alex_dev`, `sara_design`, `john_writer`, `data_guru`, `elena_ui` | Freelancer | 20–40 seeded past jobs each |

Use two browser windows (one private/incognito) to be both sides at once:

1. **Freelancer** (`john_writer`): open *Build a modern responsive website*, see "Eligible", apply. A real proof is generated and verified, and the first credential is issued.
2. **Client** (`client_alice`): open the job from the dashboard. John shows "ZK Proof Verified · Credential v1", with no stats. Hire him.
3. **Freelancer:** *Mark as delivered*.
4. **Client:** approve and rate. The review joins John's private history and his credential is reissued as v2.
5. **Freelancer:** the dashboard shows one more completed job; the next application proves against v2. Rate the client too.

To issue credentials for every seeded freelancer up front: `.venv/bin/python zk_engine.py issue-missing`.

## Tests

```sh
.venv/bin/python -B -m unittest discover -s tests -v
```

Covers login, roles, CSRF, form validation, the full hiring and review loop, privacy of applicants and stats, credential issuance, public-input binding and the engine's failure paths. When `nargo` and `bb` are installed it also runs the 20 Noir circuit tests and a real end-to-end proof, including tamper detection.

## Project layout

| Path | What it is |
|---|---|
| `app.py` | Flask routes: auth, jobs, dashboards, hiring, reviews, applying |
| `database.py` | SQLite schema, versioned migrations, demo seed data |
| `generate_circuit.py` | Generates both Noir circuits (and their tests) from one template |
| `generate_prover.py` | Builds circuit inputs from the database |
| `zk_engine.py` | Compiles circuits, issues credentials, proves and verifies |
| `templates/`, `static/` | Pages and styles |
| `tests/` | Unit and integration tests |

`REVIEW.md`, `DATABASE_CHANGES.md` and `CIRCUIT_CHANGES.md` are earlier milestone notes, kept for history.

## Known limitations

- A client's dispute flag counts immediately; there is no admin review yet.
- The circuit fits up to 64 past jobs per freelancer (configurable); beyond that, proving refuses rather than truncating.
- Withdrawn applications can't be resubmitted to the same job.
- SQLite and Flask's development server suit a demo, not production traffic.
