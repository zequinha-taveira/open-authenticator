# Contributing

Thank you for contributing to Open Authenticator.

## Before opening a change

Read:

- `README.md`
- `specs.md`
- `docs/architecture.md`
- `docs/development.md`
- `SECURITY.md`

For security-sensitive work, also read `auditoria.md`.

## Design principles

1. Keep protocol logic independent from hardware.
2. Use explicit traits at hardware boundaries.
3. Prefer `no_std`-compatible core code where practical.
4. Do not introduce manufacturer-specific assumptions into the core crates.
5. Keep test vectors deterministic and portable between Rust and Python.
6. Never commit real secrets, production credentials, attestation keys, or device provisioning material.

## Changes

Small, focused changes are preferred. Include tests for behavioral changes. Changes to public APIs, protocol encodings, security invariants, or firmware interfaces should update the relevant documentation.

## Testing

Run the Python tests with:

```bash
pytest
```

When a Rust toolchain is available, run:

```bash
cargo fmt --all -- --check
cargo test --workspace
```

## Pull requests

Explain what changed, why it changed, and how it was tested. Flag compatibility, security, or protocol-vector changes explicitly.

## Security

Do not disclose an unpatched vulnerability through a normal issue or pull request. Follow `SECURITY.md`.
