# Open Authenticator Framework

Framework open source, vendor-neutral e Rust-first para autenticadores de segurança. O repositório foi desenhado para permitir que terceiros façam fork do firmware, substituam componentes e adaptem o sistema ao próprio hardware sem reescrever o núcleo do protocolo.

## Estado

Prototype / research scaffold. O simulador CTAP2 atual é intencionalmente mínimo e **não é uma implementação CTAP2 completa nem certificada**.

## Componentes

- `oa-core`: abstrações de ambiente seguro.
- `oa-ctap2`: dispatcher CTAP2 mínimo.
- `oa-simulator`: autenticador virtual em Rust.
- `python/virtual_hardware`: hardware virtual em Python.
- `python/tests`: testes com `pytest`.
- `vectors`: vetores simples de interoperabilidade.
- `auditoria.md`: modelo de ameaça e revisão assistida por IA.

## Executar

### Rust

```bash
cargo test --all
cargo run -p oa-simulator
```

### Python

```bash
python -m venv .venv
. .venv/bin/activate
pip install -U pytest
pytest -q
```

## Próximos marcos

1. CBOR canônico e mensagens CTAP2 reais.
2. `makeCredential` e `getAssertion`.
3. `Transport` + HID in-memory e USB HID.
4. `CryptoProvider` + `KeyStore`.
5. fuzzing e property tests.
6. firmware `no_std` de referência.
7. secure boot e atualização assinada.
8. conformance/interoperability suite.

## Licença

Apache-2.0 OR MIT.
