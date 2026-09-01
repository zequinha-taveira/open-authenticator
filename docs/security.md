# Segurança

## Princípios

- Chaves privadas nunca devem aparecer em logs ou vetores de teste.
- Dados sensíveis devem ser apagados de buffers temporários quando a plataforma permitir.
- A implementação deve distinguir material público, segredo persistente e estado transitório.
- Erros de protocolo devem falhar de forma determinística e sem expor segredos.
- O simulador é uma ferramenta de desenvolvimento e não substitui armazenamento seguro ou hardware resistente a ataques físicos.

## Threat model inicial

Considerar:

- entradas CTAP malformadas;
- CBOR inválido ou ambíguo;
- mensagens truncadas;
- repetição de mensagens;
- corrupção de transporte;
- armazenamento esgotado;
- reset durante operações;
- abuso de PIN/UV;
- falhas de isolamento entre tenants/credenciais;
- configuração insegura em builds de desenvolvimento.

## Escopo de auditoria

A revisão deve separar:

1. correção de protocolo;
2. segurança criptográfica;
3. isolamento e armazenamento de segredos;
4. superfícies de transporte;
5. cadeia de inicialização e atualização;
6. configuração de produção.

Nenhum resultado deste repositório deve ser interpretado como certificação de segurança.
