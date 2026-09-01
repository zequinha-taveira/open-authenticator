# BUILD

## Prerequisites

### Rust

Install a stable Rust toolchain with `rustup` and ensure `cargo` is on `PATH`.

### Python

Python 3.10+ is recommended. Create an isolated environment and install the test requirements available in the repository.

## Python virtual hardware

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip pytest
pytest
```

On Windows PowerShell, activate the environment with the corresponding `.venv` script.

## Rust workspace

From the repository root:

```bash
cargo fmt --all -- --check
cargo test --workspace
```

For a development build:

```bash
cargo build --workspace
```

## Firmware targets

The firmware portion is a reference scaffold. Board-specific builds require a supported target, linker configuration, startup/runtime support, and a board implementation.

Do not treat a successful simulator build as evidence that a physical target is production-ready.

## CI parity

Local validation should mirror the checks in `.github/workflows/` when possible. Keep protocol test vectors identical across Rust and Python implementations.

## Reproducibility

Record compiler/tool versions when investigating a build-specific problem. Avoid committing machine-specific output, credentials, or generated build directories.
