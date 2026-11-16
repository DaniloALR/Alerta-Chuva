# AlertaChuva · Cybersecurity: módulo **Guardião**

**Global Solution 2026.2 · CitizenTech · FIAP · Engenharia de Software**

| Integrante | RM |
|---|---|
| Danilo Affonso Luz Rios | 554791 |
| Lucca Natario do Vale | 95688 |
| Thiago Feltrin Geraldes | 555805 |

Módulo de privacidade do AlertaChuva. Ele cobre a missão técnica da disciplina em três frentes: **mapeamento de PII**, **Taint Analysis** e **tradução via IA**, e entrega o indicador executivo **Risco Cidadão**. É Python puro (3.10+), sem dependências externas; só os testes usam `pytest`.

> Os dados de moradores são **sintéticos** (regra da GS): os CPFs são gerados com dígitos verificadores válidos, mas não pertencem a ninguém, e nomes e ruas são inventados.

## Por que o AlertaChuva precisa disso

Para avisar quem mora em área de alagamento, o app guarda **CPF, telefone, endereço e condição de saúde** (por exemplo, "acamado" ou "cadeirante", para priorizar o resgate). Esse dado vaza com facilidade justamente nas saídas que salvam vidas: o SMS de alerta, o canal do bairro, o mapa de ocorrências, a integração com a Defesa Civil e com IA. Vazar a condição de saúde de um morador é expor um **dado sensível** (LGPD, art. 11) e dizer a qualquer pessoa onde mora alguém que não consegue sair de casa.

## Como rodar (3 comandos)

```bash
cd cyber
python -m pip install pytest          # só para os testes
python gerar_evidencias.py            # roda TUDO e gera a pasta evidencias/
```

**Painel ao vivo:**
```bash
python dashboard/server.py            # terminal 1 → abrir http://127.0.0.1:8050
python simular_atividade.py --ao-vivo # terminal 2 → o painel atualiza a cada 1,5 s
```

**Tradução com LLM real** (opcional; sem LLM, roda em modo offline com textos factuais). As evidências entregues foram geradas com o **Llama 3.2 local via Ollama**:
```powershell
ollama pull llama3.2
$env:OLLAMA_MODEL="llama3.2"          # Windows (PowerShell); no Linux/Mac: export OLLAMA_MODEL=llama3.2
python gerar_evidencias.py
```
Também funciona com a API do Claude: defina `ANTHROPIC_API_KEY` (modelo em `ALERTACHUVA_LLM_MODEL`, padrão `claude-haiku-5-5`).

## Estrutura

```
cyber/
├── guardiao/                     ← O NOVO MÓDULO
│   ├── regras_pii.json           17 regras PII declarativas (adicionar regra = editar JSON)
│   ├── pii_engine.py             motor de parsing: normalização, validadores, contexto, Base64, estruturas
│   ├── taint.py                  Taint Analysis dinâmico: fontes, propagação, sanitizadores, sinks com política
│   ├── analise_estatica.py       Taint Analysis estático (SAST) via AST
│   ├── ia_remediacao.py          tradução via LLM (Claude / Ollama / offline) com guarda de PII
│   └── risco.py                  indicador Risco Cidadão
├── prototipo/                    backend do AlertaChuva auditado (10 vulnerabilidades plantadas, ver tabela)
│   ├── moradores.py              cadastro sintético (fonte de taint)
│   ├── saidas.py                 7 sinks com política (SMS, canal público, mapa, Defesa Civil, API, LLM, log)
│   └── servico_alerta.py         regras de negócio
├── dashboard/                    painel executivo (server.py + index.html, sem CDN)
├── tests/test_guardiao.py        59 testes
├── simular_atividade.py          um dia de chuva forte: ANTES (sem Guardião) × DEPOIS (com Guardião)
├── gerar_evidencias.py           gera tudo em evidencias/
└── evidencias/                   ← AUDITORIA DO PROTÓTIPO (já gerada)
```

## 1. Motor de parsing PII (critério: robustez, 3,0)

**17 regras** em `regras_pii.json`, em 7 categorias com peso LGPD: identificação (CPF, RG), **saúde** (condições, CID-10, cartão SUS), **credenciais** (senha, string de conexão, JWT, API keys, Bearer), financeiro (cartão), localização (endereço, CEP, GPS), contato (telefone, e-mail) e data de nascimento.

O que o torna robusto, e não um simples "grep de regex":

| Técnica | Exemplo que ele pega |
|---|---|
| Normalização Unicode, invisíveis e URL-decode | `cpf ５２９９８２２４７２５`, `529​.982…`, `cpf%3A%20529…` |
| Validação matemática | CPF (DV), CNS/SUS (mód. 11), cartão (Luhn), telefone (DDD real): `11111111111` **não** dispara |
| Contexto obrigatório para regras ambíguas | `nascimento 12/03/1951` dispara; `evento em 12/03/2024` não |
| Camada codificada | PII escondida em **Base64** é decodificada e reanalisada |
| Estruturas | JSON, dict, lista e query string; o **nome do campo** também é sinal (`"telefone": "11 9 8765 4321"`) |
| Mascaramento idempotente e útil | `***.***.***-25`, `(11) *****-4321`; GPS generalizado para ~1 km em vez de apagado |
| Resultado sem PII | achados guardam só máscara e HMAC-SHA256 (o CPF tem só 10⁹ combinações, então hash sem segredo seria reversível) |

Para criar uma regra nova, basta adicionar um objeto no JSON. O teste `test_regra_nova_por_configuracao` demonstra com uma placa de carro.

## 2. Taint Analysis (critério: eficácia, 3,0)

**Dinâmico** (`taint.py`): o dado vira `TStr`, uma string que carrega o rótulo (categoria, origem, titular) e a trilha de transformações. No sink, há **três camadas de detecção**:

1. **Rótulo propagado:** fluxo explícito (concatenação, `%`, `.format`, fatia, `upper()`, `join`).
2. **Valor contaminado:** pega o dado mesmo quando o rótulo se perde em **f-string**, `str()` ou reformatação (CPF sem pontos).
3. **Motor PII no conteúdo:** pega PII que nunca passou por uma fonte conhecida (texto livre de ocorrência, mensagem de exceção).

**Política por saída**, com uma decisão de projeto importante: em saídas que **levam o alerta de enchente** (SMS, mapa), a ação é **mascarar, nunca bloquear**. Tirar o CPF do SMS é bom; deixar de avisar o morador seria pior. Saídas sem valor de segurança (lista pública, API sem dono) são **bloqueadas**. A política também entende **titularidade**: o SMS pode conter o endereço *do próprio* morador, mas não o de outra pessoa. A Defesa Civil recebe endereço e saúde (LGPD art. 11, II, "e": tutela da vida), mas não o CPF.

**Estático** (`analise_estatica.py`): lê o código via AST e segue fonte → sink sem executar. Usa as **mesmas políticas** declaradas nos `@sink`. Encontra as **10 vulnerabilidades** do protótipo (tabela abaixo), reconhece o fluxo **sanitizado** e o **permitido**, e ainda detecta **segredos escritos no código**.

### Vulnerabilidades plantadas no protótipo (`prototipo/servico_alerta.py`)

| ID | Função | Saída | O que vaza |
|---|---|---|---|
| VULN-01 | `cadastrar_morador` | `log.info` | payload inteiro (CPF, senha, saúde) via f-string |
| VULN-02 | `cadastrar_morador` | `log.debug` | dado pessoal escondido em Base64 |
| VULN-03 | `emitir_alerta` | `sms.enviar` | CPF dentro do SMS de alerta |
| VULN-04 | `emitir_alerta` | `log.debug` | telefone do morador no log |
| VULN-05 | `publicar_lista_prioridade` | `canal.publicar` | saúde + endereço + telefone em canal aberto |
| VULN-06 | `exportar_defesa_civil` | `defesa_civil.exportar` | CPF desnecessário enviado à Defesa Civil |
| VULN-07 | `registrar_ocorrencia` | `llm.classificar_ocorrencia` | texto do cidadão (com PII de terceiros) para LLM externo |
| VULN-08 | `registrar_ocorrencia` | `mapa.publicar` | PII de terceiros e GPS preciso no mapa público |
| VULN-09 | `ingerir_leitura_sensor` | `log.error` | senha do broker MQTT e token na mensagem de erro |
| VULN-10 | `consultar_morador` | `api.responder` | dados entregues sem checar quem pede (IDOR) |

O teste `test_sast_encontra_todas_as_vulnerabilidades` confere que todas são detectadas.

## 3. Tradução via IA (critério: inovação na remediação, 2,0)

`ia_remediacao.py` transforma cada evento técnico em um JSON com **título, mensagem ao cidadão (até 260 caracteres, sem jargão), nível de risco, até 3 ações** ("desconfie de SMS pedindo CPF", "ligue 199") e uma **correção técnica para a equipe**. A IA também é protegida:

- **a IA é ancorada nos fatos:** o código monta uma mensagem factual correta e o LLM só a reescreve em linguagem simples. O nível de risco é calculado pelo código, não pelo modelo;
- respostas que **inventam fatos** (enchente acontecendo, "atualize o app") ou **contradizem o evento** ("você foi afetado" quando o dado foi protegido) são rejeitadas e refeitas; se falhar de novo, usa-se o texto factual (testes `test_llm_que_inventa_ou_contradiz_e_rejeitado`);
- o prompt só leva a mensagem factual e as categorias, nunca valores pessoais;
- a chamada ao LLM **é ela mesma um sink do Guardião** (`llm_externo`, mascarar);
- a resposta é validada (JSON, campos, limites) e **passa pelo motor PII** antes de chegar ao cidadão (teste `test_saida_do_llm_e_validada_e_mascarada`);
- há fallback para modo offline: o sistema de alerta não depende da IA para funcionar.

## 4. Dashboard executivo: Risco Cidadão (critério, 2,0)

```
Risco Cidadão = 100 × Σ (peso da categoria × exposição do canal × desfecho) ÷ Σ (peso × exposição)
desfecho: vazou 1,0 · mascarado 0,05 · bloqueado 0
```

A leitura é: *"de todo o dano à privacidade que o sistema poderia ter causado, quanto chegou de fato aos moradores"*. Faixas: < 15 baixo, < 40 moderado, < 70 alto, ≥ 70 crítico.

| | Antes (sem Guardião) | Depois (Guardião ativo) |
|---|---|---|
| **Risco Cidadão** | **100 (CRÍTICO)** | **3,5 (BAIXO)** |
| Vazamentos | 44 | 0 |
| Moradores com dado exposto | 17 | 0 |

## Evidências (`evidencias/`)

| Arquivo | Conteúdo |
|---|---|
| `01_testes_pytest.txt` | 59 testes passando |
| `01_motor_pii_demo.md` | entradas ofuscadas → regras → saída mascarada, mais a tabela de regras |
| `02_taint_estatico.md / .json` | SAST: 13 fluxos com linha, função, sink, categorias e status |
| `03_relatorio_auditoria.md` | **auditoria do protótipo**: antes × depois, camadas, trilhas, o que saiu, alertas da IA |
| `04_dashboard_risco_cidadao.png` | **print do painel** gerando o indicador |
| `04_dashboard_snapshot.html` | painel estático (abre no navegador, sem servidor) |
| `auditoria.jsonl` | log de auditoria (sem nenhum valor pessoal) |
| `alertas_ia.jsonl` | traduções da IA |
| `saidas/antes` × `saidas/depois` | o que **de fato saiu** em cada canal (SMS, canal público, mapa, LLM, log, Defesa Civil, API) |
