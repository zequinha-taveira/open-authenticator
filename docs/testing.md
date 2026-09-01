# Testes

## Camadas

### Unitários

Testam parsing, encoding, estados, erros e primitivas de domínio. `cargo test -p oa-core` (7 testes) cobre `InMemoryTransport` FIFO, `CtapStatusCode` roundtrip, `Algorithm` ids e `sensitive_zeroize`; `cargo test -p oa-ctap2` (15 testes) cobre `getInfo`, `makeCredential`/`getAssertion` e casos negativos.

### Protocol vectors

Os mesmos inputs/outputs devem poder ser consumidos por implementações Rust e Python.

- `vectors/*.json`: `{ "name", "request_hex", "expected_status", "description" }` — request é `CMD + CBOR`.
- Rust: `crates/oa-ctap2/src/lib.rs:1660` (`vectors_match_expected_status`) carrega todos os JSON via `serde_json` e compara `dispatch` status.
- Python: `python/tests/test_vectors.py:12` parametrizado sobre `vectors/` + testes de sequência `makeCredential→getAssertion`.
- 10 vetores atuais: `get_info`, `make_credential_basic`, `missing_param`, `duplicate_key`, `invalid_type`, `trailing_bytes`, `nonminimal`, `get_assertion_no_credentials`, `get_info_with_payload`, `invalid_command`.

### Virtual Hardware

O backend Python (`python/virtual_hardware/device.py:1`) representa `RNG` determinístico (`_entropy`), `credential store`, `counter` monotônico, `user presence`, `transport_queue` FIFO e CBOR canônico idêntico ao Rust.

### CTAP2 Simulator

O simulador Rust (`crates/oa-simulator/src/main.rs:1`) fornece implementação executável sem dispositivo físico, demonstrando `getInfo` (102 bytes CBOR), `makeCredential` (161), `getAssertion` (147) e `reset`.

### Interoperabilidade

Testes comparam bytes e resultados observáveis, evitando mocks que escondam diferenças de framing ou encoding. A suite `cargo test --all` + `pytest -q` deve passar identicamente; divergências de CBOR (map key order, minimal encoding) são detectadas pelos vetores negativos.

## Falhas injetáveis

O Virtual Hardware permite:

- `hardware.disconnect()` / `reconnect()` — `ConnectionError` em `ctap` e `transport_*`;
- `hardware.corrupt_next_frame()` — flip do primeiro byte (transporte ou request);
- `hardware.delay_ms(ms)` — `time.sleep` antes do próximo `ctap`;
- `hardware.deny_user_presence()` — próxima verificação `UP` retorna `OperationDenied` (0x27);
- `hardware.fill_storage()` — próximo `makeCredential` retorna `KeyStoreFull` (0x28);
- `hardware.reset()` — limpa `credentials`/`storage`/`counter`/`transport_queue`;
- `hardware.transport_send`/`transport_receive` — framing FIFO separado da semântica CTAP (limite `max_msg_size`, `Full` em overflow).

Ver `python/tests/test_transport_and_faults.py` e `crates/oa-core/src/lib.rs:540` (`InMemoryTransport`).

## Executar

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all      # 22 Rust
pytest -q             # 24 Python
```
