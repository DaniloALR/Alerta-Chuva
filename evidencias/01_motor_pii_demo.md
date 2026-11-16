# Motor de parsing PII: demonstração (regras v2.0.0, 17 regras)

| Entrada (sintética) | Regras disparadas | Saída mascarada |
|---|---|---|
| `Morador CPF 529.982.247-25 pediu ajuda` | BR_CPF (0.99) | `Morador CPF ***.***.***-25 pediu ajuda` |
| `cpf ５２９９８２２４７２５ (dígitos Unicode fullwidth)` | BR_CPF (0.99) | `cpf ***.***.***-25 (dígitos Unicode fullwidth)` |
| `cpf 529​.982.247-25 (caractere invisível no meio)` | BR_CPF (0.99) | `cpf ***.***.***-25 (caractere invisível no meio)` |
| `cpf%3A%20529.982.247-25 (URL-encoded)` | BR_CPF (0.99) | `cpf: ***.***.***-25 (URL-encoded)` |
| `payload=eyJjcGYiOiAiNTI5Ljk4Mi4yNDctMjUifQ== (Base64)` | BR_CPF (0.99, base64) | `payload=[BASE64 COM DADO PESSOAL] (Base64)` |
| `protocolo 11111111111 (falso positivo evitado)` | nenhuma | `protocolo 11111111111 (falso positivo evitado)` |
| `nota fiscal 52998224726 (dígito verificador inválido)` | nenhuma | `nota fiscal 52998224726 (dígito verificador inválido)` |
| `Dona Ana é cadeirante e insulino-dependente` | SAUDE_CONDICAO (0.60), SAUDE_CONDICAO (0.60) | `Dona Ana é [DADO DE SAÚDE] e [DADO DE SAÚDE]` |
| `laudo CID F32.1, cartão SUS 898 0012 3456 7891` | SAUDE_CID (0.60), BR_CNS (0.99) | `laudo [DADO DE SAÚDE], cartão SUS [DOCUMENTO OMITIDO]` |
| `erro: postgres://admin:S3nh4Forte@db.local:5432/alerta` | CRED_URL_SENHA (0.60) | `erro: postgres://***:***@db.local:5432/alerta` |
| `{"usuario": "ana", "password": "Chuva@2026"}` | CRED_SENHA (0.60) | `{"usuario": "ana", "password": "[SEGREDO REMOVIDO]"}` |
| `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJlc3AzMiJ9.c2lnbmF0dXJh` | CRED_BEARER (0.60) | `Authorization: [SEGREDO REMOVIDO]` |
| `Zap (11) 98765-4321 · e-mail ana.souza@exemplo.com.br` | TELEFONE_BR (0.99), EMAIL (0.60) | `Zap (11) *****-4321 · e-mail a***@exemplo.com.br` |
| `Mora na Rua Beira-Rio, 45, CEP 08061-300` | ENDERECO (0.60), CEP (0.74) | `Mora na [ENDEREÇO OMITIDO], CEP 08***-***` |
| `Ocorrência em -23.4912345, -46.4312345` | GEOLOC_PRECISA (0.60) | `Ocorrência em -23.49, -46.43 (aprox.)` |
| `nascimento 12/03/1951` | DATA_NASC (0.74) | `nascimento **/**/1951` |
| `evento em 12/03/2024 (data sem contexto: ignorada)` | nenhuma | `evento em 12/03/2024 (data sem contexto: ignorada)` |

## Regras configuradas

| ID | Categoria | Peso | Validador | Contexto obrigatório | Descrição |
|---|---|---|---|---|---|
| BR_CPF | IDENTIFICACAO | 10 | cpf | não | CPF com ou sem pontuação, validado pelos dígitos verificadores |
| BR_RG | IDENTIFICACAO | 10 | - | sim | RG (só com palavra de contexto, para evitar falso positivo) |
| BR_CNS | SAUDE | 10 | cns | não | Cartão Nacional de Saúde (SUS), validado pelo módulo 11 |
| SAUDE_CONDICAO | SAUDE | 10 | - | não | Condição de saúde ou vulnerabilidade (dado sensível LGPD) |
| SAUDE_CID | SAUDE | 10 | - | não | Código de doença CID-10 |
| CRED_SENHA | CREDENCIAL | 9 | - | não | Par chave=valor de senha (log, URL, JSON) |
| CRED_URL_SENHA | CREDENCIAL | 9 | - | não | String de conexão com usuário:senha (banco, broker MQTT) |
| CRED_JWT | CREDENCIAL | 9 | - | não | Token JWT |
| CRED_API_KEY | CREDENCIAL | 9 | - | não | Chaves de API (Anthropic/OpenAI, AWS, GitHub, Google) |
| CRED_BEARER | CREDENCIAL | 9 | - | não | Cabeçalho Authorization: Bearer |
| CARTAO | FINANCEIRO | 8 | luhn | não | Cartão de pagamento (Luhn) |
| TELEFONE_BR | CONTATO | 5 | telefone | não | Telefone fixo ou celular brasileiro (DDD validado) |
| EMAIL | CONTATO | 5 | - | não | Endereço de e-mail |
| ENDERECO | LOCALIZACAO | 7 | - | não | Logradouro com número (localiza a casa do morador) |
| CEP | LOCALIZACAO | 7 | - | só 8 dígitos | CEP (formato 00000-000, ou 8 dígitos com a palavra CEP por perto) |
| GEOLOC_PRECISA | LOCALIZACAO | 7 | - | não | Coordenada GPS com precisão de casa (4+ casas decimais) |
| DATA_NASC | NASCIMENTO | 4 | - | sim | Data de nascimento (com contexto) |
