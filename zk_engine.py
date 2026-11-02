import os
import subprocess
import shutil
import binascii
from generate_circuit import generate_main_nr, DEFAULT_HISTORY_CAPACITY
from generate_prover import generate_prover_toml

NARGO_BIN = os.path.expanduser("~/.nargo/bin/nargo")
BB_BIN = os.path.expanduser("~/.bb/bb")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CIRCUIT_DIR = os.path.join(BASE_DIR, "circuit")

def compile_circuit_if_needed():
    """Ensure circuit is compiled into ACIR JSON format"""
    target_json = os.path.join(CIRCUIT_DIR, "target", "circuit.json")
    # Never reuse the committed artifact from the old aggregate-input circuit.
    res = subprocess.run([NARGO_BIN, "compile"], cwd=CIRCUIT_DIR, capture_output=True, text=True)
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
    prover_data = generate_prover_toml(
        freelancer_id=freelancer_id,
        job_id=job_id,
        output_path=os.path.join(CIRCUIT_DIR, "Prover.toml"),
        num_past_jobs=num_past_jobs
    )
    generate_main_nr(output_path=os.path.join(CIRCUIT_DIR, "src", "main.nr"), num_past_jobs=num_past_jobs)
    compile_circuit_if_needed()

    # 3. Solve witness via nargo execute
    exec_res = subprocess.run(
        [NARGO_BIN, "execute", "witness"],
        cwd=CIRCUIT_DIR,
        capture_output=True,
        text=True
    )
    if exec_res.returncode != 0:
        return {
            "success": False,
            "error": "Circuit constraint violation: Applicant credentials do not satisfy job criteria.",
            "details": exec_res.stderr or exec_res.stdout,
            "prover_data": prover_data
        }

    # 4. Generate UltraHonk proof with bb prove
    target_json = os.path.join(CIRCUIT_DIR, "target", "circuit.json")
    witness_gz = os.path.join(CIRCUIT_DIR, "target", "witness.gz")
    proof_dir = os.path.join(CIRCUIT_DIR, "target", "proof")
    os.makedirs(proof_dir, exist_ok=True)

    prove_cmd = [
        BB_BIN, "prove",
        "-b", target_json,
        "-w", witness_gz,
        "-o", proof_dir,
        "--write_vk"
    ]
    prove_res = subprocess.run(prove_cmd, cwd=CIRCUIT_DIR, capture_output=True, text=True)
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
        BB_BIN, "verify",
        "-k", vk_file,
        "-p", proof_file,
        "-i", public_inputs_file
    ]
    verify_res = subprocess.run(verify_cmd, cwd=CIRCUIT_DIR, capture_output=True, text=True)
    is_verified = (verify_res.returncode == 0 and "Proof verified successfully" in (verify_res.stdout + verify_res.stderr))

    return {
        "success": True,
        "verified": is_verified,
        "proof_hex": proof_hex,
        "proof_size_bytes": len(proof_bytes),
        "prover_data": prover_data,
        "verifier_output": verify_res.stdout.strip()
    }

if __name__ == "__main__":
    res = generate_and_verify_zk_proof(3, 1)
    print("Result:", res["success"])
    if res["success"]:
        print("Proof verified:", res["verified"])
        print("Proof hex length:", len(res["proof_hex"]))
        print("Proof snippet:", res["proof_hex"][:66], "...")
