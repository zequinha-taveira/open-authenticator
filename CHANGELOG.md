# Changelog

All notable changes to this project will be documented here.

## Unreleased

### Added

- Initial Rust workspace for the universal authenticator framework.
- Protocol/device separation documented in `specs.md` and `docs/`.
- Python virtual-hardware package with `pytest` tests.
- Initial CTAP2 simulator scaffold.
- Shared test-vector directory.
- AI-assisted audit methodology in `auditoria.md`.
- Contributor, agent, build, and security guidance.

### Changed

- Repository is organized for vendor-neutral forks and replaceable hardware backends.

### Known limitations

- The current scaffold is not a complete CTAP2 implementation.
- The reference firmware is not yet a production-ready firmware image.
- The project has not undergone an independent security audit or certification.
- Physical USB/NFC/BLE interoperability is not established by the current simulator tests.
