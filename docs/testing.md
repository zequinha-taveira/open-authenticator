# Testes

## Camadas

### Unitários

Testam parsing, encoding, estados, erros e primitivas de domínio.

### Protocol vectors

Os mesmos inputs/outputs devem poder ser consumidos por implementações Rust e Python.

### Virtual Hardware

O backend Python representa recursos como armazenamento, contador, presença do usuário e transporte virtual.

### CTAP2 Simulator

O simulador Rust fornece uma implementação executável sem dispositivo físico.

### Interoperabilidade

Testes devem comparar bytes e resultados observáveis, evitando mocks que escondam diferenças de framing ou encoding.

## Falhas injetáveis

O Virtual Hardware deve permitir cenários como:

- desconexão;
- timeout;
- frame truncado;
- corrupção de bytes;
- armazenamento cheio;
- presença do usuário negada;
- reset durante uma transação.
