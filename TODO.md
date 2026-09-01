# TODO

## Core

- [ ] Stabilize public Rust traits and error model.
- [ ] Define versioning and compatibility guarantees.
- [ ] Expand protocol state-machine coverage.
- [ ] Add zeroization policy for sensitive buffers.

## CTAP/FIDO

- [ ] Implement broader CTAP2 command coverage.
- [ ] Add strict CBOR validation and negative test vectors.
- [ ] Expand COSE algorithm handling.
- [ ] Add credential-management and large-blob coverage.
- [ ] Add PIN/UV protocol coverage.
- [ ] Add attestation test vectors.

## Virtual Hardware

- [ ] Add virtual USB HID framing.
- [ ] Add virtual NFC/APDU transport.
- [ ] Add fault injection profiles.
- [ ] Add virtual secure-element backend.
- [ ] Add deterministic test mode with explicit test-only keys.

## Firmware

- [ ] Provide a minimal `no_std` reference firmware target.
- [ ] Define board-support-package contracts.
- [ ] Add secure-boot and firmware-update interfaces.
- [ ] Add rollback/anti-rollback design.

## Testing

- [ ] Cross-check Rust and Python implementations using shared vectors.
- [ ] Add property-based and fuzz testing.
- [ ] Add malformed-frame campaigns.
- [ ] Add interoperability fixtures for multiple device classes.
- [ ] Add CI checks for documentation and generated artifacts.

## Security and governance

- [ ] Establish security review checklist.
- [ ] Define release security advisory process.
- [ ] Add dependency auditing in CI.
- [ ] Add reproducible-build documentation.
- [ ] Define maintainer/reviewer policy for security-sensitive code.
