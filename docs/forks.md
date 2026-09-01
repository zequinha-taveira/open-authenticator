# Forks de terceiros

## Objetivo

Um fabricante, laboratório ou projeto comunitário deve poder criar um fork e substituir componentes sem alterar o núcleo do protocolo.

## Pontos de extensão

```text
CryptoProvider
SecureStorage
CounterStore
RandomSource
Transport
UserPresence
Indicator
Board
```

## Exemplo conceitual

```rust
let authenticator = Authenticator::new(
    MySecureElement::new(),
    MyProtectedFlash::new(),
    MyBoard::new(),
);
```

O código CTAP2 permanece comum ao projeto upstream.

## Recomendação para fabricantes

Mantenha alterações específicas em crates ou diretórios próprios. Evite modificar tipos públicos do core para atender somente um produto.

## Compatibilidade

Cada fork deve executar a suíte comum de testes, vetores e testes negativos antes de publicar uma versão de firmware.
