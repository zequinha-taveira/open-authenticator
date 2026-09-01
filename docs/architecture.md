# Arquitetura

## Objetivo

Separar completamente o domínio do protocolo do domínio do dispositivo.

```text
Application
    |
    v
Protocol Core
    |
    +--> AuthenticatorEnvironment
    |
    +--> Transport
    |
    v
Device / Hardware Abstraction
    |
    +--> USB HID
    +--> NFC / ISO 7816
    +--> BLE
    +--> Virtual Hardware
```

## Regras de dependência

1. `oa-core` não deve depender de um fabricante ou MCU.
2. `oa-ctap2` deve depender somente das abstrações necessárias ao protocolo.
3. Drivers de hardware implementam traits estáveis; não acessam detalhes internos do protocolo.
4. O simulador deve exercitar o mesmo caminho de bytes usado pelo transporte real sempre que possível.
5. Recursos específicos de fabricante devem permanecer em adapters separados.

## `no_std`

O núcleo deve permanecer compatível com `no_std` sempre que tecnicamente viável. Suporte `std` deve ficar nas bordas do sistema, simuladores e ferramentas.

## Firmware

O firmware de referência deve ser um consumidor do framework, e não a definição do framework. Um fork pode trocar placa, armazenamento, criptografia, transporte, UI e política sem reescrever CTAP2.
