# Open Authenticator Framework

Framework open source, vendor-neutral e Rust-first para autenticadores de segurança. O repositório foi desenhado para permitir que terceiros façam fork do firmware, substituam componentes e adaptem o sistema ao próprio hardware sem reescrever o núcleo do protocolo.

## Estado

Prototype / research scaffold — **M1 Protocol Core entregue**. O simulador CTAP2 agora implementa CBOR canônico, `makeCredential`/`getAssertion` com validação estrita, `Transport` desacoplado e vetores compartilhados Rust↔Python. Ainda **não é implementação CTAP2 completa nem certificada** — ver `CHANGELOG.md` M1 e `auditoria.md`.

## Componentes

- `oa-core` (`crates/oa-core:11`): traits vendor-neutral, `no_std` + `alloc`, `CtapStatusCode` canônico, `InMemoryTransport` FIFO, `CryptoProvider`/`SecureStorage`/`Transport`/`RandomSource`/`UserPresence`, `KeyHandle` zeroizável.
- `oa-ctap2` (`crates/oa-ctap2:1`): dispatcher CTAP com CBOR canônico RFC8949, 6 comandos (`getInfo`, `makeCredential`, `getAssertion`, `reset`, `clientPin`, `getNextAssertion`), validação estrita (duplicate-key, non-minimal, trailing-bytes, missingParam, etc), 15 testes + vetores.
- `oa-simulator` (`crates/oa-simulator/src/main.rs:1`): autenticador virtual determinístico com demo getInfo→makeCredential→getAssertion→reset.
- `python/virtual_hardware` (`python/virtual_hardware/device.py:1`): hardware virtual com `CborDecoder` e `VirtualSecurityKey` idênticos ao Rust, `Transport` em memória e fault injection (`disconnect`, `corrupt_next_frame`, `delay_ms`, `deny_user_presence`, `fill_storage`).
- `python/tests`: 24 testes `pytest` incluindo `test_vectors.py` parametrizado sobre `vectors/`.
- `vectors`: 10 vetores JSON compartilhados (`request_hex` + `expected_status`) consumidos por `cargo test` e `pytest`.
- `auditoria.md` + `docs/`: modelo de ameaça e revisão assistida por IA.

## Executar

### Rust

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo run -p oa-simulator
```

Saída esperada do simulador: `getInfo` CBOR (102 bytes), `makeCredential` 161 bytes, `getAssertion` 147 bytes, `reset` ok.

### Python

```bash
python -m venv .venv
# no Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -U pytest
pytest -q
# esperado: 24 passed
```

Vetores podem ser inspecionados em `vectors/` e são consumidos por ambos os lados — ver `python/tests/test_vectors.py:12` e `crates/oa-ctap2/src/lib.rs:1660`.

## Arquitetura (resumo)

Ver `specs.md` e `docs/architecture.md`. Fronteiras estáveis: `Protocol` ↔ `Device` via traits; `Transport` framing separado de `CTAP`; `Crypto` via `CryptoProvider`; `no_std` em `oa-core`/`oa-ctap2`.

## Próximos marcos (atualizado)

1. ~~CBOR canônico e mensagens CTAP2 reais~~ ✓ M1
2. ~~`makeCredential` e `getAssertion`~~ ✓ M1
3. ~~`Transport` + HID in-memory~~ ✓ (USB HID 64-byte reports pendente)
4. ~~`CryptoProvider` + `KeyStore` traits~~ ✓ (backends reais pendentes)
5. fuzzing e property tests
6. firmware `no_std` de referência
7. secure boot e atualização assinada
8. conformance/interoperability suite

## Licença

Apache-2.0 OR MIT.
