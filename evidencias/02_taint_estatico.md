# Taint Analysis estático: `prototipo/servico_alerta.py`

Resumo: **VIOLAÇÃO**: 9 · **SEGREDO NO CÓDIGO**: 2 · **SANITIZADO**: 1 · **PERMITIDO**: 1

| ID | Linha | Função | Saída (sink) | Categorias | Status | Fonte |
|---|---|---|---|---|---|---|
| SAST-01 | 26 | `cadastrar_morador` | `log.info → log_aplicacao` | CONTATO, CREDENCIAL, IDENTIFICACAO, LOCALIZACAO, NASCIMENTO, SAUDE | **VIOLAÇÃO** | parâmetro 'payload' |
| SAST-02 | 28 | `cadastrar_morador` | `log.debug → log_aplicacao` | CONTATO, CREDENCIAL, IDENTIFICACAO, LOCALIZACAO, NASCIMENTO, SAUDE | **VIOLAÇÃO** | parâmetro 'payload' |
| SAST-03 | 37 | `emitir_alerta` | `sms.enviar → sms_alerta_individual` | CONTATO, IDENTIFICACAO, LOCALIZACAO | **VIOLAÇÃO** | listar_moradores() L33.cpf; listar_moradores() L33.endereco; listar_mo |
| SAST-04 | 38 | `emitir_alerta` | `log.debug → log_aplicacao` | CONTATO | **VIOLAÇÃO** | listar_moradores() L33.telefone |
| SAST-05 | 39 | `emitir_alerta` | `log.info → log_aplicacao` | - | **SANITIZADO** |  |
| SAST-06 | 49 | `publicar_lista_prioridade` | `canal.publicar → canal_publico_bairro` | CONTATO, LOCALIZACAO, SAUDE | **VIOLAÇÃO** | listar_moradores() L46.condicao_saude; listar_moradores() L46.endereco |
| SAST-07 | 57 | `exportar_defesa_civil` | `defesa_civil.exportar → exportacao_defesa_civil` | CONTATO, IDENTIFICACAO, LOCALIZACAO, SAUDE | **VIOLAÇÃO** | listar_moradores() L56.condicao_saude; listar_moradores() L56.cpf; lis |
| SAST-08 | 60 | `exportar_defesa_civil` | `defesa_civil.exportar → exportacao_defesa_civil` | LOCALIZACAO, SAUDE | **PERMITIDO** | listar_moradores() L59.condicao_saude; listar_moradores() L59.endereco |
| SAST-09 | 63 | `registrar_ocorrencia` | `llm.classificar_ocorrencia → llm_externo` | TEXTO_LIVRE | **VIOLAÇÃO** | parâmetro 'texto' |
| SAST-10 | 64 | `registrar_ocorrencia` | `mapa.publicar → mapa_publico_ocorrencias` | TEXTO_LIVRE | **VIOLAÇÃO** | parâmetro 'texto' |
| SAST-11 | 71 | `-` | `literal no código-fonte` | CREDENCIAL | **SEGREDO NO CÓDIGO** | CRED_URL_SENHA |
| SAST-12 | 71 | `-` | `literal no código-fonte` | CREDENCIAL | **SEGREDO NO CÓDIGO** | CRED_BEARER |
| SAST-13 | 81 | `consultar_morador` | `api.responder → api_http_resposta` | CONTATO, CREDENCIAL, IDENTIFICACAO, LOCALIZACAO, NASCIMENTO, SAUDE | **VIOLAÇÃO** | obter_morador() L78 |

## Trechos

- **SAST-01** (L26, VIOLAÇÃO): `log.info(f'Novo cadastro recebido: {dados}')`
- **SAST-02** (L28, VIOLAÇÃO): `log.debug('payload bruto do app (b64): ' + bruto)`
- **SAST-03** (L37, VIOLAÇÃO): `sms.enviar(m.telefone, msg, titular=m.id)`
- **SAST-04** (L38, VIOLAÇÃO): `log.debug('SMS enviado para %s' % m.telefone)`
- **SAST-05** (L39, SANITIZADO): `log.info('Alerta entregue ao morador ' + mascarar(m.telefone))`
- **SAST-06** (L49, VIOLAÇÃO): `canal.publicar('Prioridade de resgate: ' + tjoin('; ', linhas))`
- **SAST-07** (L57, VIOLAÇÃO): `defesa_civil.exportar(linhas)`
- **SAST-08** (L60, PERMITIDO): `defesa_civil.exportar(ids)`
- **SAST-09** (L63, VIOLAÇÃO): `llm.classificar_ocorrencia(f'Classifique a ocorrência: {texto}')`
- **SAST-10** (L64, VIOLAÇÃO): `mapa.publicar({'categoria': categoria, 'relato': texto, 'local': f'{lat:.5f}, {lon:.5f}'})`
- **SAST-11** (L71, SEGREDO NO CÓDIGO): `mqtt://***:***@mqtt.alertachuva.local:1883`
- **SAST-12** (L71, SEGREDO NO CÓDIGO): `[SEGREDO REMOVIDO]`
- **SAST-13** (L81, VIOLAÇÃO): `api.responder(corpo, titular=solicitante)`
