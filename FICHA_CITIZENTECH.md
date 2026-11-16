# AlertaChuva

**Global Solution 2026.2 · CitizenTech · Engenharia de Software (3º ano)**

## Ficha da CitizenTech

| Campo | Conteúdo |
|---|---|
| **Nome** | AlertaChuva |
| **Cidade e bairro** | São Paulo (SP), **Jardim Pantanal**, São Miguel Paulista, zona leste, às margens do Rio Tietê |
| **Cidadão beneficiado** | Morador de área de risco de alagamento, que hoje descobre a chuva forte tarde demais. Prioridade para quem tem mobilidade reduzida (acamados, cadeirantes, idosos) |
| **Problema em uma frase** | Moradores do Jardim Pantanal não recebem alerta a tempo de se proteger de enchentes durante chuvas intensas |
| **Como funciona** | Sensor ESP32 mede chuva e nível da água → envia para a API → o modelo de ML estima o risco de chuva muito intensa amanhã com dados históricos do INMET → o app avisa o morador com o nível de risco e o que fazer |
| **O que cada parte faz** | **App:** alerta e registro de ocorrência · **API:** regras e dados · **ML:** previsão de risco · **ESP32:** leitura do sensor · **Linux:** hospeda a API · **Cyber:** protege dados dos moradores · **Testes:** Features e Test Cases |
| **Indicador de impacto** | Antecedência do alerta (ML: aviso na véspera, ≈ 12–24 h) e nº de moradores alertados por evento. Complementares: % de eventos de chuva muito intensa avisados (77,8% no teste) e Risco Cidadão (privacidade: 100 → 3,5) |
| **ODS** | **11** Cidades sustentáveis (meta 11.5: reduzir mortes e perdas por desastres) · **13** Ação climática (13.1: resiliência a eventos climáticos) · **3** Saúde e bem-estar (prioriza vulneráveis no resgate) |
| **Link do repositório** | `https://github.com/DaniloALR/Alerta-Chuva` |

## Estrutura do repositório

| Pasta | Disciplina | Entrega |
|---|---|---|
| [`ml/`](ml/) | Inteligência Artificial & Machine Learning | Notebook executado, `RELATORIO_ML.md`, `dados/README.md`, `requirements.txt` |
| [`cyber/`](cyber/) | Cybersecurity | Módulo Guardião (PII + Taint Analysis + IA + Risco Cidadão) e evidências |
| `prompts.md` | Todas | Registro do uso de IA como copiloto (regra da GS) |

## Como as partes conversam

```
ESP32 (nível/chuva) ──► API ──► modelo ML (INMET A701: risco de ≥20 mm amanhã)
                         │            │
                         ▼            ▼
               Guardião (Cyber) ─► app / SMS: "Risco ALTO amanhã. Suba documentos e remédios."
               mascara CPF, saúde, endereço de terceiros, senhas
```

O ML gera o nível exibido no app (BAIXO / ATENÇÃO / ALTO). Toda saída de dados (SMS, mapa de ocorrências, Defesa Civil, logs, LLM) passa pelo Guardião antes de sair.

## Dados

- **ML:** dados **reais e públicos** do INMET (estação A701, 2006–2025). Fonte, período e verificação de integridade em [`ml/dados/README.md`](ml/dados/README.md).
- **Cyber:** dados de moradores **sintéticos** (nenhum dado pessoal real, regra da GS).
