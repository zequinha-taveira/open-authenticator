# Security Policy

## Scope

This project is a vendor-neutral reference framework for security authenticators. It includes protocol code, hardware abstractions, a virtual hardware environment, and development tooling.

The project is **not a certified security product**. Production deployments must perform their own threat modeling, secure-boot review, key-management review, side-channel assessment, and independent security audit.

## Reporting vulnerabilities

Do not disclose unpatched vulnerabilities in public issues. Use the repository's private security-reporting mechanism when enabled. Include:

- affected component and version/commit;
- reproducible steps or a minimal proof of concept;
- security impact and assumptions;
- whether the issue affects the reference simulator, virtual hardware, or production firmware;
- proposed mitigation, when known.

Do not include real private keys, production credentials, attestation keys, or other sensitive material.

## Security expectations

Changes involving cryptography, credential handling, PIN/UV, counters, attestation, secure storage, parsing, transport framing, firmware update, or privilege boundaries require focused tests and documentation.

Security fixes should include regression tests where practical and should be reviewed independently of the original author when project governance permits.

## Supported versions

Only explicitly supported release lines should be considered for security fixes. Development snapshots may contain incomplete security controls.

## AI-assisted review

AI tools may assist with code review, threat enumeration, invariant checking, and test generation. AI output is advisory and must not be treated as an audit, certification, or proof of security. Human review remains mandatory for security-sensitive changes.
