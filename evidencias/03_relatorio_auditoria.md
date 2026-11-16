# Auditoria do protótipo AlertaChuva: Taint Analysis em ação

Mesmo código e mesmo roteiro de uso (um dia de chuva forte: cadastro, alerta por SMS, ocorrências, sensor ESP32, API, Defesa Civil), executado duas vezes: **sem** e **com** o Guardião.

| Indicador | Antes (sem Guardião) | Depois (Guardião ativo) |
|---|---|---|
| **Risco Cidadão (0–100)** | **100.0 (CRÍTICO)** | **3.5 (BAIXO)** |
| Saídas com dado pessoal auditadas | 46 | 46 |
| Vazamentos | 44 | 0 |
| Bloqueados | 0 | 2 |
| Mascarados | 0 | 42 |
| Permitidos pela política (base legal) | 2 | 2 |
| Moradores com dado exposto | 17 | 0 |
| Moradores protegidos | 0 | 17 |

## Detecção por camada (achados em saídas proibidas)

| Camada | Achados |
|---|---|
| 1-rótulo propagado | 114 |
| 2-valor contaminado | 24 |
| 3-conteúdo (motor PII) | 70 |

## Decisões por saída (sink), fase DEPOIS

| Saída | Política | Decisões |
|---|---|---|
| `log_aplicacao` | mascarar | MASCARADO: 19 |
| `sms_alerta_individual` | mascarar | MASCARADO: 14 |
| `llm_externo` | mascarar | MASCARADO: 3 |
| `mapa_publico_ocorrencias` | mascarar | MASCARADO: 5 |
| `canal_publico_bairro` | bloquear | BLOQUEADO: 1 |
| `api_http_resposta` | bloquear | BLOQUEADO: 1, PERMITIDO: 1 |
| `exportacao_defesa_civil` | mascarar | MASCARADO: 1, PERMITIDO: 1 |

## Exemplos de trilha (fonte → transformações → saída)

- **MASCARADO** em `log_aplicacao` (servico_alerta.py:26 em cadastrar_morador()): IDENTIFICACAO · camada *2-valor contaminado* · `rótulo perdido (f-string/str/reformatação), valor reconhecido`
- **MASCARADO** em `log_aplicacao` (servico_alerta.py:28 em cadastrar_morador()): IDENTIFICACAO · camada *3-conteúdo (motor PII)* · `regra BR_CPF (base64)`
- **MASCARADO** em `sms_alerta_individual` (servico_alerta.py:37 em emitir_alerta()): IDENTIFICACAO · camada *1-rótulo propagado* · `banco.moradores[M-0001].cpf → concat×4 → SINK`
- **MASCARADO** em `log_aplicacao` (servico_alerta.py:38 em emitir_alerta()): CONTATO · camada *1-rótulo propagado* · `banco.moradores[M-0001].telefone → % → SINK`
- **MASCARADO** em `llm_externo` (servico_alerta.py:63 em registrar_ocorrencia()): IDENTIFICACAO · camada *3-conteúdo (motor PII)* · `regra BR_CPF (texto)`
- **MASCARADO** em `mapa_publico_ocorrencias` (servico_alerta.py:64 em registrar_ocorrencia()): IDENTIFICACAO · camada *3-conteúdo (motor PII)* · `regra BR_CPF (texto)`
- **BLOQUEADO** em `canal_publico_bairro` (servico_alerta.py:49 em publicar_lista_prioridade()): SAUDE · camada *1-rótulo propagado* · `banco.moradores[M-0013].condicao_saude → join → concat → SINK`
- **BLOQUEADO** em `canal_publico_bairro` (servico_alerta.py:49 em publicar_lista_prioridade()): SAUDE · camada *2-valor contaminado* · `rótulo perdido (f-string/str/reformatação), valor reconhecido`

## O que efetivamente saiu do sistema (primeira linha de cada saída)

**sms_enviados.log**
- ANTES: `para=(11) 99975-9042 | AlertaChuva: Ana Lúcia Santos, risco ALTO de alagamento amanhã (42 mm) na Rua do Aterro, 255. Seu cadastro: CPF 588.139.986-27. Suba documentos e remédios.`
- DEPOIS: `para=(11) 99975-9042 | AlertaChuva: Ana Lúcia Santos, risco ALTO de alagamento amanhã (42 mm) na Rua do Aterro, 255. Seu cadastro: CPF ***.***.***-27. Suba documentos e remédios.`

**canal_publico.log**
- ANTES: `Prioridade de resgate: Ana Lúcia Santos (gestante) - Rua do Aterro, 255 - (11) 99975-9042; Rita de Cássia Lima (cadeirante) - Rua Beira-Rio, 634 - (11) 91003-8392; Severino Pereira (acamado) - Rua da Várzea, 96 - (11) 98749-3149; Luzia Oliveira (oxigênio domic…`
- DEPOIS: `6 famílias com prioridade de resgate foram informadas à Defesa Civil.`

**mapa_publico.jsonl**
- ANTES: `{"categoria": "pessoa ilhada", "relato": "Meu vizinho Seu Zé, CPF 390.533.447-05, é cadeirante e está ilhado na Rua Beira-Rio, 45. Liga (11) 97777-1234", "local": "-23.49123, -46.43123"}`
- DEPOIS: `{"categoria": "pessoa ilhada", "relato": "Meu vizinho Seu Zé, CPF ***.***.***-05, é [DADO DE SAÚDE] e está ilhado na [ENDEREÇO OMITIDO]. Liga (11) *****-1234", "local": "-23.49, -46.43 (aprox.)"}`

**llm_prompts.log**
- ANTES: `Classifique a ocorrência: Meu vizinho Seu Zé, CPF 390.533.447-05, é cadeirante e está ilhado na Rua Beira-Rio, 45. Liga (11) 97777-1234`
- DEPOIS: `Classifique a ocorrência: Meu vizinho Seu Zé, CPF ***.***.***-05, é [DADO DE SAÚDE] e está ilhado na [ENDEREÇO OMITIDO]. Liga (11) *****-1234`

**app.log**
- ANTES: `INFO  Novo cadastro recebido: {'nome': 'Morador Teste A', 'cpf': '529.982.247-25', 'telefone': '(11) 98765-4321', 'senha': 'Chuva@1234', 'endereco': 'Rua das Garças, 77', 'cep': '08062-120', 'condicao_saude': 'gestante'}`
- DEPOIS: `INFO  Novo cadastro recebido: {'nome': 'Morador Teste A', 'cpf': '***.***.***-25', 'telefone': '(11) *****-4321', 'senha': '[CREDENCIAL OMITIDO]', 'endereco': '[ENDEREÇO OMITIDO]', 'cep': '08***-***', 'condicao_saude': '[DADO DE SAÚDE]'}`

**defesa_civil_export.jsonl**
- ANTES: `[{"cpf": "588.139.986-27", "endereco": "Rua do Aterro, 255", "telefone": "(11) 99975-9042", "condicao_saude": "gestante"}, {"cpf": "751.362.701-01", "endereco": "Rua Beira-Rio, 634", "telefone": "(11) 91003-8392", "condicao_saude": "cadeirante"}, {"cpf": "205.…`
- DEPOIS: `[{"cpf": "***.***.***-27", "endereco": "Rua do Aterro, 255", "telefone": "(11) 99975-9042", "condicao_saude": "gestante"}, {"cpf": "***.***.***-01", "endereco": "Rua Beira-Rio, 634", "telefone": "(11) 91003-8392", "condicao_saude": "cadeirante"}, {"cpf": "***.…`

## Alertas ao cidadão gerados pela IA (amostra da fase DEPOIS)

- **Seu CPF e dados de saúde foram protegidos** (log_aplicacao, risco baixo): Tivemos cuidado para esconder seu CPF e informações de saúde. O alerta de chuva chegou normalmente e nada foi exposto.  
  *Correção p/ equipe:* Nunca interpolar o objeto/payload inteiro no log. Logar só o ID: log.info(f"cadastro {m.id}") ou usar mascarar().  *Fonte:* llm:ollama/llama3.2
- **Seu CPF protegido no SMS de alerta** (sms_alerta_individual, risco baixo): Tiramos seu CPF da mensagem antes do envio. Nada vazou e o aviso de chuva chegou normalmente para você.  
  *Correção p/ equipe:* Remover documento do texto do SMS; identificar o morador pelo ID e confirmar identidade pelo app.  *Fonte:* llm:ollama/llama3.2
- **Seu telefone e e-mail foram protegidos** (log_aplicacao, risco baixo): Nada foi exposto nos registros internos do sistema. Você recebeu seu alerta de chuva normalmente e tudo está bem.  
  *Correção p/ equipe:* Nunca interpolar o objeto/payload inteiro no log. Logar só o ID: log.info(f"cadastro {m.id}") ou usar mascarar().  *Fonte:* llm:ollama/llama3.2
- **Seu CPF e dados de saúde foram protegidos** (llm_externo, risco baixo): Nada foi exposto e o aviso de chuva chegou normalmente para você. Lembre-se de que apenas a Defesa Civil precisa de sua condição de saúde para te ajudar.  
  *Correção p/ equipe:* Mascarar o texto antes do prompt; preferir modelo local para conteúdo do cidadão.  *Fonte:* llm:ollama/llama3.2

> Dados de moradores 100% sintéticos. O arquivo `auditoria.jsonl` não contém nenhum valor pessoal: só categoria, origem, local do código e valor já mascarado (ver teste `test_auditoria_nao_contem_pii`).
