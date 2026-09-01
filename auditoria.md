# Auditoria de Segurança Assistida por IA — Open Authenticator Framework

## 1. Escopo

Este documento define a metodologia inicial para revisão de segurança do monorepo. A IA é usada como **revisor auxiliar**, gerador de hipóteses e verificador de consistência; não é autoridade final nem substitui auditoria criptográfica, revisão humana ou testes de conformidade.

Escopo atual:

- Rust workspace e interfaces de abstração.
- Simulador CTAP2 inicial.
- Hardware virtual em Python.
- Testes `cargo test` e `pytest`.
- Separação entre protocolo, ambiente seguro e transporte.
- Base para forks de firmware de terceiros.

## 2. Estado atual

**Protótipo / não pronto para produção.**

A implementação CTAP2 presente neste repositório é deliberadamente mínima e serve para validar a arquitetura e o pipeline de testes. Ela **não deve ser apresentada como uma implementação FIDO2/CTAP2 completa** nem usada em uma Security Key real.

## 3. Modelo de ameaça

Ativos principais:

1. Chaves privadas e material secreto.
2. Credenciais residentes e metadados.
3. PIN/UV e decisões de presença do usuário.
4. Contadores de assinatura.
5. Estado de provisionamento e atualização de firmware.
6. Integridade das mensagens entre transporte e protocolo.

Adversários considerados:

- aplicação host maliciosa;
- tráfego de transporte manipulado;
- firmware modificado por terceiros;
- armazenamento corrompido;
- falhas de energia/reinicialização;
- entradas CTAP/CBOR malformadas;
- desenvolvedor introduzindo regressões no fork.

## 4. Regras de arquitetura auditáveis

### A. Independência de fabricante

O core não deve importar SDK de fabricante, driver de placa ou protocolo proprietário.

### B. Fronteira de privilégio

O protocolo não acessa diretamente flash, TRNG, GPIO, USB ou secure element. Tudo deve passar por traits bem definidos.

### C. Criptografia

Não implementar primitivas criptográficas novas dentro do framework. Usar bibliotecas maduras e, para firmware de produção, avaliar implementação/validação compatível com o alvo.

### D. Segredos

Evitar material secreto em `String`, logs, panic messages ou estruturas clonáveis sem necessidade. Avaliar zeroização e movimentação de memória antes da primeira versão de produção.

### E. CBOR / CTAP2

O próximo estágio deve substituir o envelope mínimo do simulador por codificação/decodificação CTAP2 conforme a especificação aplicável, com testes de entradas inválidas, limites, tipos incorretos e canonicalização.

### F. Atualizações

O firmware final precisa de secure boot/verified boot, anti-rollback e política de atualização assinada. Isso não está implementado no protótipo.

## 5. Checklist de revisão assistida por IA

A cada pull request, executar uma revisão estruturada com um modelo de IA sobre o diff:

1. **Boundary review** — procurar acesso indevido entre protocol/device/crypto/storage.
2. **Input review** — procurar panic, índices não validados, overflows, parsing permissivo e estados impossíveis.
3. **Secret review** — procurar logs, cópias, serialização e persistência de segredos.
4. **State-machine review** — procurar transições que permitam bypass de user presence, PIN/UV ou políticas.
5. **Concurrency review** — procurar condições de corrida, reentrância e uso após reset/desconexão.
6. **Supply-chain review** — revisar mudanças em dependências, features e build scripts.
7. **Fork review** — verificar que implementações de placa não alteram invariantes do protocolo.
8. **Test-gap review** — gerar casos de teste para cada achado potencial.

## 6. Prompt recomendado para revisão por IA

```text
Você é um revisor sênior de segurança de firmware Rust.
Analise apenas o diff fornecido.

Objetivos:
- encontrar vulnerabilidades reais ou plausíveis;
- separar certeza de hipótese;
- identificar violações das fronteiras arquiteturais;
- sugerir testes reproduzíveis;
- não inventar requisitos não suportados pela especificação.

Para cada achado, informe:
- severidade: Critical/High/Medium/Low/Info;
- arquivo e linha;
- cenário de exploração;
- pré-condições;
- impacto;
- correção mínima;
- teste de regressão proposto;
- confiança: alta/média/baixa.

Não declare conformidade FIDO, segurança criptográfica ou ausência de vulnerabilidades.
Essas conclusões exigem validação adicional.
```

## 7. Gates de CI

O merge deve exigir, no mínimo:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
pytest -q
```

Para releases de firmware, adicionar posteriormente:

```text
cargo audit
cargo deny check
SBOM
reproducible-build check
firmware signature verification
fuzzing
protocol conformance tests
hardware-in-the-loop tests
```

## 8. Findings iniciais

### OA-001 — CTAP2 incompleto

**Severidade:** High para produção / Info para o protótipo.

O simulador implementa somente um envelope mínimo para `authenticatorGetInfo`; não existe ainda CBOR CTAP2 completo, `makeCredential`, `getAssertion`, PIN/UV, attestation ou HID framing.

**Ação:** manter explicitamente como protótipo e não anunciar conformidade.

### OA-002 — Criptografia real ausente

**Severidade:** High para produção.

O core atual define abstrações, mas não implementa armazenamento protegido, geração de chaves, assinatura ou isolamento de segredos.

**Ação:** implementar `CryptoProvider`/`KeyStore` atrás de interfaces, com backend de referência seguro e testes específicos.

### OA-003 — Transporte não implementado

**Severidade:** Medium para o protótipo.

Ainda não existe USB HID/NFC/BLE real.

**Ação:** criar `Transport` e manter teste in-memory como primeiro backend.

### OA-004 — Secure boot / update ausentes

**Severidade:** Critical para produção de hardware.

O repositório não implementa cadeia de confiança de boot nem atualização assinada.

**Ação:** especificar formato de imagem, manifest, assinatura, anti-rollback e recuperação antes do hardware de produção.

## 9. Princípio de auditoria

> O framework deve ser fácil de auditar porque suas fronteiras são pequenas, explícitas e substituíveis.

Uma IA pode ajudar a **encontrar problemas**. Ela não pode, sozinha, certificar o framework como seguro, criptograficamente correto ou conforme qualquer padrão.
