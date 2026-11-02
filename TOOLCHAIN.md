# Reproducible Noir toolchain

The tested presentation toolchain is pinned to:

- Nargo / Noir: `1.0.0-beta.26`
- Barretenberg: `5.2.0`
- Proof system: UltraHonk

These exact versions compiled, proved, and verified this repository on 2 November 2026 under Ubuntu in WSL.

## Install in Ubuntu/WSL

```sh
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
~/.nargo/bin/noirup --version 1.0.0-beta.26

curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
~/.bb/bbup -v 5.2.0
```

Confirm versions:

```sh
~/.nargo/bin/nargo --version
~/.bb/bb --version
```

## Run circuit tests and a witness

From `circuit/`:

```sh
~/.nargo/bin/nargo test
~/.nargo/bin/nargo compile
~/.nargo/bin/nargo execute witness
```

## Generate and verify a proof

From `circuit/`:

```sh
mkdir -p target/proof
~/.bb/bb prove -b target/circuit.json -w target/witness.gz -o target/proof --write_vk
~/.bb/bb verify -k target/proof/vk -p target/proof/proof -i target/proof/public_inputs
```

The verifier must print `Proof verified successfully`.

## Application integration

When Flask runs on Windows, `zk_engine.py` discovers these binaries in the configured WSL distribution (`Ubuntu` by default), converts the project path to its `/mnt/<drive>/...` form, and runs the pinned toolchain there. Override the distribution with `FREELA_WSL_DISTRO`. Native installations can be selected with `NARGO_BIN` and `BB_BIN`.

The application checks both versions before compiling. It does not fall back to a simulated proof: missing or incompatible tools produce an explicit error instead of a false verified result.
