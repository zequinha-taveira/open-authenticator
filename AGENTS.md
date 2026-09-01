# AGENTS.md

This file defines repository-local guidance for automated coding agents and AI-assisted development.

## Repository mission

Build a vendor-neutral, open-source framework for security authenticators. Protocol code and device code must remain independently replaceable.

## Architecture rules

- `core` and protocol crates must not depend on a specific MCU, USB controller, secure element, OS, or manufacturer.
- Hardware integrations must implement stable abstractions instead of reaching into protocol internals.
- Keep transport framing separate from application/protocol semantics.
- Preserve `no_std` compatibility for layers intended to run in embedded environments.

## Change discipline

- Inspect existing code and tests before changing interfaces.
- Prefer minimal, composable changes over broad rewrites.
- Add or update tests for behavior changes.
- Do not silently change wire formats or public trait semantics.
- Keep generated files and documentation synchronized when applicable.

## Security

- Treat key material, credentials, attestation material, and provisioning data as sensitive.
- Never add secrets to fixtures, examples, or commits.
- Do not describe a code review as an audit or certification.
- Security-sensitive changes require human review.

## Validation

Run the smallest relevant validation first, then broader checks when tooling is available. Report unavailable toolchains honestly instead of assuming success.
