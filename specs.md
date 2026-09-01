# Open Authenticator Framework — Especificação Inicial

**Status:** Draft / Research Prototype  
**Versão:** 0.1  
**Objetivo:** definir as fronteiras estáveis do framework universal de autenticadores, incluindo simulador, hardware virtual e firmware Rust forkável por terceiros.

## 1. Visão

O Open Authenticator Framework (OAF) é um framework open source, vendor-neutral e Rust-first para construir, testar, simular e portar autenticadores de segurança.

O projeto deve permitir que um terceiro:

- faça fork do firmware de referência;
- substitua componentes individuais;
- adapte o sistema a uma placa/MCU/secure element próprios;
- mantenha os protocolos em conformidade sem reimplementar o núcleo;
- execute os testes sem possuir hardware físico.

A arquitetura separa quatro domínios:

```text
Application
    │
    ▼
Protocol Layer ──────── CTAP2 / FIDO / COSE / CBOR
    │
    ▼
Authenticator Core ─── state / credentials / policy
    │
    ├───────────────┬─────────────────┐
    ▼               ▼                 ▼
Crypto          Storage           Transport
    │               │                 │
    ▼               ▼           USB / NFC / BLE
Hardware Abstraction Layer
    │
    ├── simulator
    ├── virtual hardware
    └── real boards / vendor forks
```

## 2. Princípios normativos

Os termos **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** e **MAY** são usados com o sentido normativo usual de especificações técnicas.

### 2.1 Neutralidade de fabricante

`oa-core`, `oa-protocol`, `oa-ctap2`, `oa-cbor` e `oa-cose` MUST NOT depender de SDK, driver ou API proprietária de um fabricante específico.

### 2.2 Independência de hardware

A lógica de protocolo MUST NOT acessar diretamente GPIO, flash, USB controller, secure element, TRNG ou periféricos.

Toda interação física deve ocorrer por traits/interfaces.

### 2.3 Substituibilidade

Cada backend de crypto, storage, transport e board SHOULD ser substituível sem modificar o núcleo do protocolo.

### 2.4 `no_std`

As crates de protocolo e core SHOULD suportar `no_std` e, quando necessário, `alloc` como feature separada.

### 2.5 Segurança por fronteiras

A fronteira entre protocolo, ambiente seguro e transporte deve ser explícita no tipo/API. Implementações de hardware não devem precisar conhecer detalhes internos de outras camadas.

## 3. Camada de protocolo

Responsabilidades:

- parsing e validação de mensagens;
- CBOR;
- COSE;
- CTAP2;
- máquinas de estado;
- modelo de credenciais;
- política de PIN/UV e user presence;
- códigos de erro;
- serialização de requests/responses.

A camada de protocolo MUST ser testável sem hardware.

### 3.1 Interface conceitual

```rust
pub trait Authenticator {
    type Error;

    fn get_info(&mut self)
        -> Result<AuthenticatorInfo, Self::Error>;

    fn make_credential(
        &mut self,
        request: MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Self::Error>;

    fn get_assertion(
        &mut self,
        request: GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Self::Error>;
}
```

Essa interface é conceitual no release 0.1. A API final deve ser estabilizada após o núcleo CTAP2 real estar implementado.

## 4. Camada de ambiente seguro

A camada de ambiente fornece primitivas ao autenticador sem expor implementação concreta.

```rust
pub trait CryptoProvider {
    type Error;

    fn generate_key(
        &mut self,
        algorithm: Algorithm,
    ) -> Result<KeyHandle, Self::Error>;

    fn sign(
        &mut self,
        key: &KeyHandle,
        message: &[u8],
    ) -> Result<Signature, Self::Error>;
}

pub trait SecureStorage {
    type Error;

    fn read(
        &mut self,
        key: StorageKey,
    ) -> Result<Option<Vec<u8>>, Self::Error>;

    fn write(
        &mut self,
        key: StorageKey,
        value: &[u8],
    ) -> Result<(), Self::Error>;
}
```

Implementações possíveis:

- software backend para desenvolvimento;
- storage protegido em MCU;
- secure element;
- TPM/HSM adapter;
- backend específico de fornecedor.

Um backend de desenvolvimento MUST ser explicitamente identificado como não adequado para produção.

## 5. Transporte

Transporte é independente do protocolo.

```rust
pub trait Transport {
    type Error;

    fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error>;

    fn receive(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<usize, Self::Error>;
}
```

Backends planejados:

```text
InMemoryTransport
UsbHidTransport
NfcTransport
BleTransport
Iso7816Transport
```

`InMemoryTransport` é obrigatório para o simulador e a suíte de testes.

## 6. Virtual Hardware

O Virtual Hardware (VH) reproduz recursos de hardware por software.

### 6.1 Recursos mínimos

```text
VirtualHardware
├── RNG
├── secure storage model
├── credential store
├── signature engine
├── monotonic counter
├── user presence
├── reset/power-cycle
├── transport endpoint
└── fault injection
```

### 6.2 Python backend

O backend Python existe para testes, cenários e fault injection. Ele não deve ser importado pelo firmware Rust de produção.

O protocolo de teste preferencial deve transportar bytes reais de CTAP/HID-like, permitindo validar framing e parsing.

### 6.3 Falhas simuláveis

O VH SHOULD permitir:

```python
hardware.reset()
hardware.disconnect()
hardware.corrupt_next_frame()
hardware.delay_ms(100)
hardware.deny_user_presence()
hardware.fill_storage()
```

Esses recursos servem para validar estados de erro e recuperação.

## 7. CTAP2 Simulator

O simulador Rust deve representar um autenticador em memória e utilizar exatamente os mesmos contratos de core destinados ao firmware.

Objetivos:

1. executar testes sem hardware;
2. validar state machines;
3. fornecer referência executável;
4. permitir testes de interoperabilidade;
5. servir como alvo de fuzzing.

O simulador MUST NOT ser apresentado como implementação completa ou certificada até que os comandos, CBOR, criptografia, storage e testes de conformidade estejam completos.

### 7.1 Evolução mínima

```text
Fase 1: authenticatorGetInfo
Fase 2: CBOR real
Fase 3: makeCredential
Fase 4: getAssertion
Fase 5: PIN/UV
Fase 6: resident credentials
Fase 7: attestation
Fase 8: transport framing
Fase 9: conformance
```

## 8. Firmware de referência

O firmware de referência deve ser uma implementação `no_std` que consuma somente as abstrações públicas.

Estrutura conceitual:

```text
firmware/reference
    │
    ├── board
    ├── crypto
    ├── storage
    ├── transport
    └── app
           │
           ▼
      oa-authenticator
```

O firmware deve evitar lógica criptográfica e protocolo específica de placa.

## 9. Forks de terceiros

Um fork pode substituir:

| Componente | Substituição permitida |
|---|---|
| MCU/SoC | MUST |
| Secure Element | MUST |
| RNG | MUST |
| Crypto backend | MUST |
| Storage | MUST |
| USB stack | MUST |
| NFC stack | SHOULD |
| BLE stack | SHOULD |
| UI / LED / botão | SHOULD |
| Bootloader | SHOULD |
| Policy provider | SHOULD |
| CTAP/FIDO protocol core | SHOULD NOT sem razão de compatibilidade |

A compatibilidade deve ser comprovada pela suíte comum de testes.

## 10. Testes

O projeto deve ter quatro níveis:

### Unidade

Testes de tipos, parsing, estado e funções puras.

### Protocolo

Vectors de requests/responses e casos inválidos.

### Interoperabilidade

O mesmo vector executado por Rust, Python e implementações de forks.

### Hardware-in-the-loop

Quando hardware existir, os mesmos casos críticos devem ser executados através do transporte físico.

## 11. Vetores de teste

Os vetores devem ser versionados em `vectors/` e independentes da linguagem.

Formato inicial recomendado:

```json
{
  "name": "get-info-basic",
  "request": "...",
  "expected": "..."
}
```

Quando CTAP2 real estiver implementado, os vetores devem representar bytes/canonical CBOR conforme a especificação adotada e incluir casos positivos e negativos.

## 12. Compatibilidade de versões

A compatibilidade pública deve ser definida por:

```text
Protocol Version
API Version
Vector Version
Firmware ABI (quando aplicável)
```

Mudanças em traits públicas MUST ser acompanhadas por changelog e migração.

O framework deve preferir compatibilidade semântica a compatibilidade interna de implementação.

## 13. Build e CI

CI mínima:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
pytest -q
```

CI de segurança prevista:

```text
cargo audit
cargo deny
fuzzing
SBOM
reproducible builds
signature verification
protocol conformance
```

O merge deve bloquear falhas nos testes obrigatórios.

## 14. Auditoria assistida por IA

A IA é uma ferramenta de revisão, não uma autoridade de certificação.

Cada PR SHOULD ter revisão assistida focada em:

```text
architecture boundaries
input validation
secret handling
state-machine transitions
panic / overflow / memory safety
concurrency
dependency changes
test gaps
fork-specific regressions
```

A saída da IA deve indicar:

- localização;
- severidade;
- hipótese de exploração;
- impacto;
- confiança;
- teste de regressão;
- correção sugerida.

Nenhum relatório gerado por IA deve declarar sozinho “seguro”, “certificado” ou “conforme”.

## 15. Threat model mínimo

Atacantes considerados:

- host malicioso;
- transporte adulterado;
- entrada CTAP/CBOR malformada;
- armazenamento corrompido;
- falha de energia;
- firmware de fork comprometido;
- downgrade de firmware;
- abuso de APIs administrativas;
- falhas de integração de hardware.

Ativos:

- chaves privadas;
- credenciais;
- PIN/UV state;
- counters;
- attestation material;
- firmware e estado de atualização.

## 16. Requisitos para produção

O protótipo MUST NOT ser usado como Security Key de produção até existir, no mínimo:

1. implementação CTAP2 real e revisada;
2. gerenciamento de chaves apropriado ao hardware;
3. armazenamento protegido;
4. secure boot / verified boot;
5. atualização assinada e anti-rollback;
6. tratamento de reset e power-loss;
7. fuzzing do parser/protocolo;
8. conformance/interoperability testing;
9. revisão de dependências;
10. auditoria humana independente.

## 17. Critério de sucesso do framework

O framework será considerado arquiteturalmente bem-sucedido quando um terceiro puder:

```text
fork repository
      ↓
replace board
      ↓
replace crypto backend
      ↓
replace storage
      ↓
replace transport
      ↓
run common Rust + Python test suite
      ↓
obtain same protocol behavior
```

sem modificar desnecessariamente o núcleo do protocolo.

## 18. Próximos milestones

### M0 — Scaffold

Workspace, simulador, Python VH e CI.

### M1 — Protocol Core

CBOR, erros, state machine e primeiros vectors reais.

### M2 — CTAP2

`getInfo`, `makeCredential`, `getAssertion` e respostas válidas/inválidas.

### M3 — Virtual Interoperability

Rust ↔ Python usando bytes reais e fault injection.

### M4 — Firmware

`no_std`, board abstraction e primeiro target embarcado.

### M5 — Hardware Adapters

USB HID, NFC, BLE e secure-element backends.

### M6 — Security

Fuzzing, secure boot, signed update, anti-rollback e auditoria independente.

### M7 — Ecosystem

Documentação para forks, compatibility matrix, conformance suite e releases versionadas.

## 19. Não-objetivos da versão 0.1

A versão inicial não pretende:

- implementar todos os protocolos de autenticação existentes;
- garantir certificação FIDO;
- substituir uma auditoria independente;
- oferecer segurança equivalente a um secure element por software;
- padronizar detalhes de cada fabricante;
- tornar uma implementação experimental apropriada para produção.

## 20. Decisão arquitetural principal

```text
                 STABLE CONTRACTS
                       │
        ┌──────────────┼──────────────┐
        │              │              │
      Protocol       Device         Security
        │              │              │
        └──────────────┼──────────────┘
                       │
                 Multiple backends
                       │
          ┌────────────┼────────────┐
          │            │            │
        Python        Rust        Hardware
        VH/Tests      VM          Forks
```

**O protocolo é a referência estável; hardware, fornecedor e backend são implementações substituíveis.**
