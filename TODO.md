# TODO

## Core

- [x] Stabilize public Rust traits and error model. (CtapStatusCode, Algorithm, Transport, CryptoProvider, SecureStorage, Authenticator)
- [ ] Define versioning and compatibility guarantees.
- [x] Expand protocol state-machine coverage. (getInfo, makeCredential, getAssertion, reset, clientPin, getNextAssertion)
- [x] Add zeroization policy for sensitive buffers. (zeroize feature + sensitive_zeroize helper)

## CTAP/FIDO

- [x] Implement broader CTAP2 command coverage. (CBOR canônico + 6 comandos com validação estrita)
- [x] Add strict CBOR validation and negative test vectors. (minimal encoding, duplicate keys, trailing bytes, 10 vetores em vectors/)
- [x] Expand COSE algorithm handling. (Es256, EdDSA, Rs256 com cose_id)
- [ ] Add credential-management and large-blob coverage.
- [x] Add PIN/UV protocol coverage. (stub com PinNotSet/PinRequired/PinAuthInvalid + verificação UP/UV)
- [ ] Add attestation test vectors. (fmt none implementado, packed/TPM pendentes)

## Virtual Hardware

- [x] Add virtual USB HID framing. (InMemoryTransport como base; USB HID 64-byte reports como próximo passo)
- [ ] Add virtual NFC/APDU transport.
- [x] Add fault injection profiles. (disconnect, corrupt_next_frame, delay_ms, deny_user_presence, fill_storage)
- [ ] Add virtual secure-element backend.
- [x] Add deterministic test mode with explicit test-only keys. (VirtualEnvironment/VirtualSecurityKey com entropy determinístico)

## Firmware

- [ ] Provide a minimal `no_std` reference firmware target.
- [ ] Define board-support-package contracts.
- [ ] Add secure-boot and firmware-update interfaces.
- [ ] Add rollback/anti-rollback design.

## Testing

- [x] Cross-check Rust and Python implementations using shared vectors. (vectors/*.json consumidos por cargo test e pytest)
- [ ] Add property-based and fuzz testing.
- [x] Add malformed-frame campaigns. (duplicate key, trailing bytes, non-minimal CBOR, invalid types)
- [x] Add interoperability fixtures for multiple device classes. (Rust ↔ Python com mesma CBOR/sha256/authData)
- [ ] Add CI checks for documentation and generated artifacts.

## Security and governance

- [ ] Establish security review checklist.
- [ ] Define release security advisory process.
- [ ] Add dependency auditing in CI.
- [ ] Add reproducible-build documentation.
- [ ] Define maintainer/reviewer policy for security-sensitive code.
