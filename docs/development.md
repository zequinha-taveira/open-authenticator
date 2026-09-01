# Desenvolvimento

## Pré-requisitos

- Rust estável com Cargo.
- Python 3.11+.
- `pytest`.
- Git.

## Testes Python

```bash
python -m pytest -q
```

## Testes Rust

```bash
cargo test --all
```

## Verificação do workspace

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Princípio de desenvolvimento

Alterações de protocolo devem incluir vetores ou testes de regressão. Alterações de hardware devem implementar ou atualizar traits sem acoplar a camada de protocolo a um dispositivo concreto.

## Repository-level guidance

See the root `BUILD.md`, `CONTRIBUTING.md`, `AGENTS.md`, `SECURITY.md`, and `TODO.md` for build, contribution, AI-agent, security, and roadmap rules.
