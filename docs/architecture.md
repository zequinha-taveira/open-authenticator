# Arquitetura

## Objetivo

Separar completamente o domínio do protocolo do domínio do dispositivo.

```text
Application
    |
    v
Protocol Core (oa-ctap2, CBOR canônico, CtapStatusCode)
    |
    +--> RandomSource / UserPresence / MonotonicCounter / CryptoProvider / SecureStorage
    |
    +--> Transport (trait) — framing separado de semântica
    |
    v
Device / Hardware Abstraction (oa-core traits)
    |
    +--> InMemoryTransport (testes, FIFO, fault injection) — crates/oa-core/src/lib.rs:540
    +--> USB HID (planejado, 64-byte reports)
    +--> NFC / ISO 7816 (planejado)
    +--> BLE (planejado)
    +--> Virtual Hardware (Python, python/virtual_hardware/device.py:1)
```

## Regras de dependência

1. `oa-core` não deve depender de um fabricante ou MCU — apenas `alloc`, `zeroize` opcional e `sha2` em `oa-ctap2`.
2. `oa-ctap2` depende somente de `oa-core` + `sha2` + `thiserror`; toda criptografia real virá de crates maduras via `CryptoProvider`.
3. Drivers de hardware implementam traits estáveis (`Transport`, `SecureStorage`, `CryptoProvider`); não acessam detalhes internos do protocolo.
4. O simulador (`crates/oa-simulator/src/main.rs:1`) exercita exatamente o mesmo `Ctap2::dispatch` e `cbor::*` usados pelo firmware, sobre transporte em memória.
5. Recursos específicos de fabricante permanecem em adapters separados (ex.: `firmware/board`).

## `no_std`

`oa-core` (`#![cfg_attr(not(feature = "std"), no_std)]`) e `oa-ctap2` são `no_std` + `alloc` compatíveis. Features: `std` (default), `alloc`, `zeroize-derive`. `std` fica nas bordas (simulador, testes, `InMemoryTransport`). `cargo check --no-default-features` deve passar.

## CBOR e Transporte

- `oa-ctap2::cbor` implementa RFC8949 canônico mínimo (major 0..5,7; rejeita indefinidos/tags, non-minimal, duplicate-key, trailing-bytes) — ver auditoria.md §5E.
- `Transport::send`/`receive` operam sobre `&[u8]` frames; HID/NFC/BLE adapters fazem chunking; `InMemoryTransport` é FIFO puro para testes.

## Firmware

O firmware de referência deve ser um consumidor do framework, e não a definição do framework. Um fork pode trocar placa, armazenamento, criptografia, transporte, UI e política sem reescrever CTAP2 — contratos em `oa_core::{Transport, SecureStorage, CryptoProvider, Authenticator}` e `specs.md` §9.

## Validação

`cargo fmt --check` + `cargo clippy -- -D warnings` + `cargo test --all` (22) + `pytest -q` (24) são gates mínimos. Vetores em `vectors/` garantem interoperabilidade Rust↔Python.
