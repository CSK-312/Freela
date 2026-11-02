import os
import subprocess
import shutil
import binascii
from dataclasses import dataclass
from generate_circuit import generate_main_nr, DEFAULT_HISTORY_CAPACITY
from generate_prover import generate_prover_toml

NARGO_VERSION = "1.0.0-beta.26"
BB_VERSION = "5.2.0"
WSL_DISTRO = os.environ.get("FREELA_WSL_DISTRO", "Ubuntu")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CIRCUIT_DIR = os.path.join(BASE_DIR, "circuit")


@dataclass(frozen=True)
class Tool:
    path: str
    wsl: bool = False


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

def compile_circuit_if_needed(nargo=None):
    """Ensure circuit is compiled into ACIR JSON format"""
    target_json = os.path.join(CIRCUIT_DIR, "target", "circuit.json")
    # Never reuse the committed artifact from the old aggregate-input circuit.
    nargo = nargo or get_toolchain()[0]
    res = _run(nargo, "compile")
    if res.returncode != 0:
        raise RuntimeError(f"Nargo compilation error: {res.stderr}")
    return target_json

def generate_and_verify_zk_proof(freelancer_id: int, job_id: int, num_past_jobs: int = DEFAULT_HISTORY_CAPACITY):
    """
    Executes the full pipeline:
      1. Generates main.nr (if customized) and ensures compilation
      2. Generates Prover.toml for (Person A, Job B) from DB
      3. Solves witness via `nargo execute`
      4. Generates cryptographic UltraHonk proof & VK via `bb prove`
      5. Cryptographically verifies proof via `bb verify`
    
    Returns dict with proof hex, verification status, timings/logs.
    """
    # Validate and export every stored record before invoking the proof tools.
    nargo, bb = get_toolchain()
    prover_data = generate_prover_toml(
        freelancer_id=freelancer_id,
        job_id=job_id,
        output_path=os.path.join(CIRCUIT_DIR, "Prover.toml"),
        num_past_jobs=num_past_jobs
    )
    generate_main_nr(output_path=os.path.join(CIRCUIT_DIR, "src", "main.nr"), num_past_jobs=num_past_jobs)
    compile_circuit_if_needed(nargo)

    # 3. Solve witness via nargo execute
    exec_res = _run(nargo, "execute", "witness")
    if exec_res.returncode != 0:
        return {
            "success": False,
            "error": "Circuit constraint violation: Applicant credentials do not satisfy job criteria.",
            "details": exec_res.stderr or exec_res.stdout,
            "prover_data": prover_data
        }

    # 4. Generate UltraHonk proof with bb prove
    # Tool arguments use POSIX separators because these commands may run in WSL.
    target_json = "target/circuit.json"
    witness_gz = "target/witness.gz"
    proof_dir = os.path.join(CIRCUIT_DIR, "target", "proof")
    os.makedirs(proof_dir, exist_ok=True)

    prove_cmd = [
        "prove",
        "-b", target_json,
        "-w", witness_gz,
        "-o", "target/proof",
        "--write_vk"
    ]
    prove_res = _run(bb, *prove_cmd)
    if prove_res.returncode != 0:
        return {
            "success": False,
            "error": "Barretenberg prove failed",
            "details": prove_res.stderr or prove_res.stdout
        }

    # Read binary proof file and convert to hex for DB storage & presentation
    proof_file = os.path.join(proof_dir, "proof")
    vk_file = os.path.join(proof_dir, "vk")
    public_inputs_file = os.path.join(proof_dir, "public_inputs")

    with open(proof_file, "rb") as pf:
        proof_bytes = pf.read()
        proof_hex = "0x" + binascii.hexlify(proof_bytes).decode("ascii")

    # 5. Cryptographically verify proof using Barretenberg verifier
    verify_cmd = [
        "verify",
        "-k", "target/proof/vk",
        "-p", "target/proof/proof",
        "-i", "target/proof/public_inputs"
    ]
    verify_res = _run(bb, *verify_cmd)
    is_verified = (verify_res.returncode == 0 and "Proof verified successfully" in (verify_res.stdout + verify_res.stderr))

    if not is_verified:
        return {
            "success": False,
            "verified": False,
            "error": "Barretenberg verification failed",
            "details": (verify_res.stdout + verify_res.stderr).strip()
        }

    return {
        "success": True,
        "verified": is_verified,
        "proof_hex": proof_hex,
        "proof_size_bytes": len(proof_bytes),
        "prover_data": prover_data,
        "verifier_output": (verify_res.stdout + verify_res.stderr).strip()
    }

if __name__ == "__main__":
    res = generate_and_verify_zk_proof(3, 1)
    print("Result:", res["success"])
    if res["success"]:
        print("Proof verified:", res["verified"])
        print("Proof hex length:", len(res["proof_hex"]))
        print("Proof snippet:", res["proof_hex"][:66], "...")
