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

### M1 — Protocol Core (2026-09-01)

#### Core (oa-core)
- `no_std` + `alloc` compatível com feature gates `std`/`alloc`/`zeroize-derive`.
- `CtapStatusCode` canônico (0x00..0x40) com `as_u8`/`from_u8` e `Display`.
- `Algorithm` expandido (Es256, EdDSA, Rs256) com `cose_id`/`from_cose_id`.
- `AuthenticatorInfo` detalhado (versions, extensions, aaguid, options, maxMsgSize, pinUvAuthProtocols, transports, algorithms, etc).
- `Options` com `always_uv`, `plat`, `client_pin`.
- Traits estáveis: `CryptoProvider`, `SecureStorage`, `Transport`, `RandomSource`, `UserPresence`, `MonotonicCounter`, `SecureEnvironment` (compat) e `Authenticator` conceitual.
- `Transport` + `InMemoryTransport` (FIFO, disconnect, corrupt_next, limites) e impl para `Vec<Vec<u8>>`.
- `KeyHandle`/`Signature` com `ZeroizeOnDrop` opcional e `sensitive_zeroize` helper.

#### CTAP2 (oa-ctap2)
- CBOR canônico mínimo RFC8949 em `cbor` mod (major types 0..5,7, validação de encoding mínimo, rejeição de indefinidos/tags, duplicate-key, trailing-bytes).
- `encode_get_info` CBOR real com 7 chaves canônicas (versions, aaguid, options, maxMsgSize, pinUvAuthProtocols, transports, algorithms).
- Dispatcher com 6 comandos: `getInfo`, `makeCredential`, `getAssertion`, `reset`, `clientPin` (stub com códigos PinNotSet/PinRequired/PinAuthInvalid/InvalidSubcommand) e `getNextAssertion`.
- Validação estrita: MissingParameter (0x14), InvalidCbor (0x12), CborUnexpectedType (0x11), InvalidParameter (0x02), InvalidLength (0x03), LimitExceeded (0x15), UnsupportedAlgorithm (0x26), CredentialExcluded (0x19), KeyStoreFull (0x28), NoCredentials (0x2E), OperationDenied (0x27), etc.
- State-machine: contador monotônico, credential store em memória, excludeList, UP/UV checks via `SecureEnvironment`, SHA-256 para `rpIdHash`/`authData`, COSE key dummy para attestedCredData, assinatura dummy SHA256(authData||clientDataHash).
- 15 testes Rust incluindo `vectors_match_expected_status` que consome `vectors/*.json`.

#### Simulator (oa-simulator)
- `VirtualEnvironment` determinístico (entropy incremental).
- Demo completo: getInfo → makeCredential → getAssertion → reset com CBOR helpers expostos (`cbor::encode_*`).

#### Virtual Hardware (Python)
- `CborDecoder` espelhando Rust (minimal-encoding, duplicate-key, trailing-bytes).
- `VirtualSecurityKey` com CBOR canônico idêntico ao Rust, SHA-256, authData, COSE, credential store, `InMemoryTransport`-like queue e fault injection (`disconnect`/`reconnect`, `corrupt_next_frame`, `delay_ms`, `deny_user_presence`, `fill_storage`).
- Transporte framing separado da semântica (transport_send/receive FIFO).

#### Vetores e Testes
- 10 vetores em `vectors/` (getInfo, makeCredential básico, missingParam, duplicateKey, invalidType, trailingBytes, nonMinimal, getAssertionNoCredentials, getInfoWithPayload, invalidCommand) consumidos por Rust e Python.
- `python/tests/test_vectors.py` parametrizado + `test_transport_and_faults.py` (15 testes Python totais; total 24 com vetores).
- `cargo test --all` (22 testes Rust) e `pytest -q` (24) ambos verdes; `cargo clippy -- -D warnings` e `cargo fmt --check` passando.

### Known limitations

- Attestation ainda `fmt none` apenas; packed/self/enterprise pendentes.
- PIN/UV token criptográfico (pinUvAuthToken) não realiza ECDH real — retorna códigos de erro apropriados.
- LargeBlob, credMgmt e NFC/BLE transports pendentes.
- Firmware `no_std` de referência ainda scaffold.
- Não há auditoria independente; não usar em produção.

