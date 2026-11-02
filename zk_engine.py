import os
import re
import secrets
import subprocess
import shutil
import binascii
import hashlib
import tempfile
import threading
from dataclasses import dataclass
from generate_circuit import generate_main_nr, generate_commit_nr, DEFAULT_HISTORY_CAPACITY
from generate_prover import generate_prover_toml, generate_commit_toml, field_hex, FIELD_MODULUS
from database import get_db_connection

NARGO_VERSION = "1.0.0-beta.26"
BB_VERSION = "5.2.0"
WSL_DISTRO = os.environ.get("FREELA_WSL_DISTRO", "Ubuntu")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CIRCUIT_DIR = os.path.join(BASE_DIR, "circuit")
COMMIT_DIR = os.path.join(BASE_DIR, "circuit_commit")
# Per-request working folders live inside the project so WSL can map their paths.
RUNS_DIR = os.path.join(BASE_DIR, ".local", "zk-runs")


@dataclass(frozen=True)
class Tool:
    path: str
    wsl: bool = False


@dataclass(frozen=True)
class Build:
    nargo: Tool
    bb: Tool
    capacity: int
    vk_path: str
    vk_hash: str


def _resolve_tool(name, env_name, linux_relative):
    configured = os.environ.get(env_name)
    native = configured or shutil.which(name)
    if native and os.path.isfile(native):
        return Tool(native)
    home_candidate = os.path.expanduser(linux_relative)
    if os.path.isfile(home_candidate):
        return Tool(home_candidate)
    if os.name == "nt" and shutil.which("wsl"):
        result = subprocess.run(
            ["wsl", "-d", WSL_DISTRO, "--", "sh", "-lc",
             f'test -x "$HOME/{linux_relative[2:]}" && printf %s "$HOME/{linux_relative[2:]}"'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            return Tool(result.stdout.strip(), wsl=True)
    raise RuntimeError(
        f"{name} was not found. Install the pinned version or set {env_name}. "
        f"Expected {name} version: {NARGO_VERSION if name == 'nargo' else BB_VERSION}."
    )


def _run(tool, *args, cwd=CIRCUIT_DIR, timeout=300):
    if not tool.wsl:
        command = [tool.path, *args]
        return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    absolute_cwd = os.path.abspath(cwd)
    drive, tail = os.path.splitdrive(absolute_cwd)
    if not drive:
        raise RuntimeError(f"Cannot map Windows path into WSL: {absolute_cwd}")
    linux_cwd = f"/mnt/{drive[0].lower()}{tail.replace(chr(92), '/')}"
    command = ["wsl", "-d", WSL_DISTRO, "--cd", linux_cwd, "--", tool.path, *args]
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def get_toolchain():
    nargo = _resolve_tool("nargo", "NARGO_BIN", "~/.nargo/bin/nargo")
    bb = _resolve_tool("bb", "BB_BIN", "~/.bb/bb")
    nargo_version = _run(nargo, "--version", timeout=30)
    bb_version = _run(bb, "--version", timeout=30)
    if nargo_version.returncode != 0 or NARGO_VERSION not in (nargo_version.stdout + nargo_version.stderr):
        raise RuntimeError(f"Expected Nargo {NARGO_VERSION}; found: {(nargo_version.stdout + nargo_version.stderr).strip()}")
    if bb_version.returncode != 0 or BB_VERSION not in (bb_version.stdout + bb_version.stderr):
        raise RuntimeError(f"Expected Barretenberg {BB_VERSION}; found: {(bb_version.stdout + bb_version.stderr).strip()}")
    return nargo, bb


def _output(result):
    return (result.stdout + result.stderr).strip()


_build_lock = threading.Lock()
_builds = {}


def prepare_circuits(num_past_jobs=DEFAULT_HISTORY_CAPACITY):
    """Generate and compile both circuits and pin the verification key, once per process.

    Every proof is later verified against this VK, never one produced alongside the proof.
    """
    with _build_lock:
        if num_past_jobs in _builds:
            return _builds[num_past_jobs]
        nargo, bb = get_toolchain()
        generate_main_nr(os.path.join(CIRCUIT_DIR, "src", "main.nr"), num_past_jobs)
        generate_commit_nr(os.path.join(COMMIT_DIR, "src", "main.nr"), num_past_jobs)
        for package in (CIRCUIT_DIR, COMMIT_DIR):
            res = _run(nargo, "compile", cwd=package)
            if res.returncode != 0:
                raise RuntimeError(f"Nargo compilation error in {os.path.basename(package)}: {_output(res)}")
        res = _run(bb, "write_vk", "-b", "target/circuit.json", "-o", "target/vk", cwd=CIRCUIT_DIR)
        vk_path = os.path.join(CIRCUIT_DIR, "target", "vk", "vk")
        if res.returncode != 0 or not os.path.isfile(vk_path):
            raise RuntimeError(f"Barretenberg could not write the verification key: {_output(res)}")
        with open(vk_path, "rb") as f:
            vk_hash = hashlib.sha256(f.read()).hexdigest()
        _builds[num_past_jobs] = Build(nargo, bb, num_past_jobs, vk_path, vk_hash)
        return _builds[num_past_jobs]


def _scratch_copy(package_dir):
    """An isolated copy of a compiled package, so concurrent requests never share files."""
    os.makedirs(RUNS_DIR, exist_ok=True)
    run_dir = tempfile.mkdtemp(prefix="run-", dir=RUNS_DIR)
    shutil.copy2(os.path.join(package_dir, "Nargo.toml"), run_dir)
    shutil.copytree(os.path.join(package_dir, "src"), os.path.join(run_dir, "src"))
    # Compiled artifacts only (named after the package); no keys, proofs or witnesses.
    shutil.copytree(os.path.join(package_dir, "target"), os.path.join(run_dir, "target"),
                    ignore=shutil.ignore_patterns("vk", "proof", "*.gz"))
    return run_dir


def decode_public_inputs(raw):
    """Barretenberg writes public inputs as consecutive 32-byte big-endian field elements."""
    if len(raw) % 32:
        raise ValueError("Malformed public inputs file.")
    return [int.from_bytes(raw[i:i + 32], "big") for i in range(0, len(raw), 32)]


def _expected_public_inputs(public_inputs):
    return [int(public_inputs[key], 16) if isinstance(public_inputs[key], str) else public_inputs[key]
            for key in ("min_rating_scaled", "min_completed_jobs", "min_on_time_rate", "max_disputes",
                        "job_id", "applicant_id", "commitment")]


def issue_credential(freelancer_id, num_past_jobs=DEFAULT_HISTORY_CAPACITY):
    """Commit to the freelancer's full current history with a fresh secret salt.

    Called when a job is reviewed (and once for existing history). Proofs must match the
    newest credential, so history edited or dropped after issuance can no longer prove.
    """
    build = prepare_circuits(num_past_jobs)
    salt = field_hex(secrets.randbelow(FIELD_MODULUS))
    run_dir = _scratch_copy(COMMIT_DIR)
    try:
        info = generate_commit_toml(freelancer_id, salt, os.path.join(run_dir, "Prover.toml"), num_past_jobs)
        res = _run(build.nargo, "execute", cwd=run_dir)
        match = re.search(r"Circuit output:\s*(?:Field\()?(0x[0-9a-fA-F]+|\d+)", _output(res))
        if res.returncode != 0 or not match:
            raise RuntimeError(f"Could not compute the history commitment: {_output(res)}")
        value = match.group(1)
        commitment = field_hex(int(value, 16) if value.startswith("0x") else int(value))
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)

    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        version = conn.execute("SELECT COALESCE(MAX(version), 0) + 1 FROM credentials WHERE freelancer_id = ?",
                               (freelancer_id,)).fetchone()[0]
        conn.execute("""INSERT INTO credentials (freelancer_id, version, commitment, salt, record_count)
            VALUES (?, ?, ?, ?, ?)""", (freelancer_id, version, commitment, salt, info["record_count"]))
        conn.commit()
    finally:
        conn.close()
    return {"version": version, "commitment": commitment, "record_count": info["record_count"]}


def generate_and_verify_zk_proof(freelancer_id: int, job_id: int, num_past_jobs: int = DEFAULT_HISTORY_CAPACITY):
    """
    Executes the full pipeline in an isolated working folder:
      1. Builds Prover.toml for (freelancer, job) from the DB and their current credential
      2. Solves the witness via `nargo execute` (fails if ineligible or history != credential)
      3. Generates the UltraHonk proof via `bb prove`
      4. Verifies it via `bb verify` against the pinned verification key
      5. Checks the proof's public inputs are this job's thresholds, this applicant and
         their current commitment

    Returns dict with proof hex, verification status and what it was checked against.
    """
    build = prepare_circuits(num_past_jobs)
    run_dir = _scratch_copy(CIRCUIT_DIR)
    try:
        # Validate and export every stored record before invoking the proof tools.
        prover_data = generate_prover_toml(
            freelancer_id=freelancer_id,
            job_id=job_id,
            output_path=os.path.join(run_dir, "Prover.toml"),
            num_past_jobs=num_past_jobs
        )

        exec_res = _run(build.nargo, "execute", "witness", cwd=run_dir)
        if exec_res.returncode != 0:
            return {
                "success": False,
                "error": "No valid proof exists: your history does not meet this job's requirements or does not match your issued credential.",
                "details": _output(exec_res),
                "prover_data": prover_data
            }

        # The trusted VK is copied in because tool arguments must be relative paths for WSL.
        shutil.copy2(build.vk_path, os.path.join(run_dir, "trusted_vk"))
        prove_res = _run(build.bb, "prove", "-b", "target/circuit.json", "-w", "target/witness.gz",
                         "-k", "trusted_vk", "-o", "proof", cwd=run_dir)
        proof_file = os.path.join(run_dir, "proof", "proof")
        if prove_res.returncode != 0 or not os.path.isfile(proof_file):
            return {"success": False, "error": "Barretenberg prove failed", "details": _output(prove_res)}

        verify_res = _run(build.bb, "verify", "-k", "trusted_vk", "-p", "proof/proof",
                          "-i", "proof/public_inputs", cwd=run_dir)
        if verify_res.returncode != 0 or "Proof verified successfully" not in _output(verify_res):
            return {
                "success": False,
                "verified": False,
                "error": "Barretenberg verification failed",
                "details": _output(verify_res)
            }

        # A valid proof only matters if it is about this job, this applicant and their current credential.
        with open(os.path.join(run_dir, "proof", "public_inputs"), "rb") as f:
            verified_inputs = decode_public_inputs(f.read())
        if verified_inputs != _expected_public_inputs(prover_data["public_inputs"]):
            return {
                "success": False,
                "verified": False,
                "error": "The proof's public inputs do not match this job, applicant and credential.",
            }

        with open(proof_file, "rb") as pf:
            proof_bytes = pf.read()
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)

    return {
        "success": True,
        "verified": True,
        "proof_hex": "0x" + binascii.hexlify(proof_bytes).decode("ascii"),
        "proof_size_bytes": len(proof_bytes),
        "prover_data": prover_data,
        "credential_id": prover_data["credential_id"],
        "vk_hash": build.vk_hash,
        "verifier_output": _output(verify_res)
    }


def issue_missing_credentials(num_past_jobs=DEFAULT_HISTORY_CAPACITY):
    """Issue a first credential to every freelancer who has history but none yet."""
    conn = get_db_connection()
    try:
        ids = [row[0] for row in conn.execute("""
            SELECT DISTINCT r.freelancer_id FROM reputation_records r
            WHERE NOT EXISTS (SELECT 1 FROM credentials c WHERE c.freelancer_id = r.freelancer_id)""")]
    finally:
        conn.close()
    return {freelancer_id: issue_credential(freelancer_id, num_past_jobs) for freelancer_id in ids}


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["issue-missing"]:
        for freelancer_id, credential in issue_missing_credentials().items():
            print(f"Freelancer {freelancer_id}: credential v{credential['version']} over {credential['record_count']} jobs")
    elif len(sys.argv) == 3 and sys.argv[1] == "issue":
        print(issue_credential(int(sys.argv[2])))
    else:
        res = generate_and_verify_zk_proof(3, 1)
        print("Result:", res["success"], res.get("error", ""))
        if res["success"]:
            print("Proof hex length:", len(res["proof_hex"]))
            print("Verified against VK", res["vk_hash"][:16], "and credential", res["credential_id"])
