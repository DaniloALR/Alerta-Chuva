from __future__ import annotations

import json
import os
import re
import time
import urllib.request

from .pii_engine import motor
from .taint import sink

CAT_PT = {"IDENTIFICACAO": "seu CPF ou documento", "SAUDE": "uma informação sobre sua saúde",
          "CREDENCIAL": "uma senha ou chave de acesso", "LOCALIZACAO": "o endereço da sua casa",
          "CONTATO": "seu telefone ou e-mail", "FINANCEIRO": "dados de pagamento", "NASCIMENTO": "sua data de nascimento"}
SINK_PT = {"log_aplicacao": "nos registros internos do sistema", "sms_alerta_individual": "dentro de um SMS de alerta",
           "canal_publico_bairro": "no canal aberto do bairro, que qualquer pessoa pode ler",
           "mapa_publico_ocorrencias": "no mapa público de ocorrências",
           "exportacao_defesa_civil": "no arquivo enviado à Defesa Civil", "api_http_resposta": "para quem consultou o sistema sem ser você",
           "llm_externo": "para um serviço de inteligência artificial externo"}
CAT_CURTO = {"IDENTIFICACAO": "Seu CPF", "SAUDE": "Seu dado de saúde", "CREDENCIAL": "Sua senha",
             "LOCALIZACAO": "Seu endereço", "CONTATO": "Seu telefone", "FINANCEIRO": "Seu dado de pagamento",
             "NASCIMENTO": "Sua data de nascimento"}
SINK_CURTO = {"log_aplicacao": "no registro interno", "sms_alerta_individual": "no SMS de alerta",
              "canal_publico_bairro": "no canal do bairro", "mapa_publico_ocorrencias": "no mapa público",
              "exportacao_defesa_civil": "no envio à Defesa Civil", "api_http_resposta": "na consulta ao sistema",
              "llm_externo": "na IA externa"}
NIVEL = {"publico": "alto", "http": "alto", "terceiro": "médio", "exportacao": "médio", "log": "médio", "titular": "baixo"}
ACOES_CIDADAO = {
    "IDENTIFICACAO": "Desconfie de ligações ou SMS que peçam para \"confirmar\" seu CPF. O AlertaChuva nunca pede.",
    "SAUDE": "Ninguém precisa saber da sua condição de saúde para te ajudar. Ela só vai para a Defesa Civil.",
    "CREDENCIAL": "Troque sua senha do app por precaução e não repita a mesma senha em outros serviços.",
    "LOCALIZACAO": "Se alguém desconhecido aparecer dizendo que veio pelo AlertaChuva, ligue 199 (Defesa Civil).",
    "CONTATO": "Os alertas oficiais vêm sempre do mesmo número. Ignore links de outros números.",
    "FINANCEIRO": "Acompanhe seu extrato e avise o banco se notar algo estranho.",
    "NASCIMENTO": "Fique atento a pedidos de dados por telefone."}
CORRECAO_DEV = {
    "log_aplicacao": "Nunca interpolar o objeto/payload inteiro no log. Logar só o ID: log.info(f\"cadastro {m.id}\") ou usar mascarar().",
    "sms_alerta_individual": "Remover documento do texto do SMS; identificar o morador pelo ID e confirmar identidade pelo app.",
    "canal_publico_bairro": "Publicar só dados agregados (\"12 famílias prioritárias\"); lista nominal vai apenas para a Defesa Civil.",
    "mapa_publico_ocorrencias": "Rodar motor.mascarar() no texto livre antes de publicar; guardar o original criptografado.",
    "exportacao_defesa_civil": "Trocar CPF por pseudonimizar(); a Defesa Civil precisa de endereço e condição, não de documento.",
    "api_http_resposta": "Exigir autenticação e checar solicitante == titular (controle de acesso por objeto, OWASP API1).",
    "llm_externo": "Mascarar o texto antes do prompt; preferir modelo local para conteúdo do cidadão."}

PROMPT_VERSAO = "6"
PROMPT_SISTEMA = """Você reescreve avisos de privacidade do AlertaChuva, app de alerta de enchente do Jardim Pantanal (São Paulo), para moradores comuns.
Regras obrigatórias:
1. Use SOMENTE os fatos recebidos. Não invente nada: nada de água subindo, enchente acontecendo, evacuação, celular invadido ou app desatualizado.
2. Se o fato disser que o dado NÃO foi exposto, deixe claro que está tudo bem e que nada vazou. Nunca diga "você foi afetado" nem "comprometido".
3. Português do Brasil simples, frases curtas, tom calmo. Sem termos técnicos (taint, sink, log, PII, LLM).
4. "titulo": até 50 caracteres, específico: diga qual dado foi protegido e onde (ex.: "Seu CPF protegido no SMS"). Não fale de chuva no título. "mensagem_cidadao": até 220 caracteres, frases completas.
5. "o_que_fazer": até 3 ações curtas, escolhidas entre as sugeridas.
Responda APENAS com JSON: {"titulo": "...", "mensagem_cidadao": "...", "o_que_fazer": ["..."]}"""

EXEMPLO_USUARIO = json.dumps({"fato": "O sistema de proteção escondeu seu CPF ou documento antes de aparecer dentro de um SMS de alerta. Nada foi exposto.",
                              "dado_foi_exposto": False, "acoes_sugeridas": ["Desconfie de ligações ou SMS que peçam para \"confirmar\" seu CPF. O AlertaChuva nunca pede."]},
                             ensure_ascii=False)
EXEMPLO_RESPOSTA = json.dumps({"titulo": "Seu CPF foi protegido no SMS de alerta",
                               "mensagem_cidadao": "Tiramos seu CPF da mensagem antes do envio. Nada vazou e o aviso de chuva chegou normalmente para você.",
                               "o_que_fazer": ["Desconfie de SMS que peça seu CPF: o AlertaChuva nunca pede."]}, ensure_ascii=False)


def _evento_para_prompt(ev: dict) -> dict:
    viol = [a for a in ev["achados"] if a["violacao"]]
    return {"saida": ev["sink"], "tipo_saida": ev["tipo"], "decisao": ev["decisao"],
            "categorias_expostas": sorted({a["categoria"] for a in viol}),
            "camadas_deteccao": sorted({a["camada"] for a in viol}), "local_codigo": ev["local"],
            "qtd_moradores_afetados": len(ev.get("titulares", []))}


@sink("llm_externo", tipo="terceiro", acao="mascarar")
def _chamar_llm(sistema: str, usuario: str) -> tuple[str, str]:
    mensagens = [{"role": "user", "content": EXEMPLO_USUARIO}, {"role": "assistant", "content": EXEMPLO_RESPOSTA},
                 {"role": "user", "content": usuario}]
    if os.environ.get("ANTHROPIC_API_KEY"):
        modelo = os.environ.get("ALERTACHUVA_LLM_MODEL", "claude-haiku-5-5")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps({"model": modelo, "max_tokens": 600, "system": sistema,
                             "messages": mensagens}).encode(),
            headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            corpo = json.load(r)
        return "".join(b.get("text", "") for b in corpo["content"]), f"llm:anthropic/{modelo}"
    if os.environ.get("OLLAMA_MODEL"):
        host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
        req = urllib.request.Request(
            f"{host}/api/chat", headers={"content-type": "application/json"},
            data=json.dumps({"model": os.environ["OLLAMA_MODEL"], "stream": False, "format": "json", "keep_alive": "15m",
                             "options": {"num_predict": 400, "temperature": 0.2},
                             "messages": [{"role": "system", "content": sistema}, *mensagens]}).encode())
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.load(r)["message"]["content"], f"llm:ollama/{os.environ['OLLAMA_MODEL']}"
    raise RuntimeError("nenhum LLM configurado")


_PROIBIDO_SE_PROTEGIDO = re.compile(r"(?i)\b(afetad|comprometid|invadid|vazou|vazaram|vazad|expost|roubad|hacke)\w*")
_INVENCAO = re.compile(r"(?i)\b(água|agua|enchente|alagamento|alagad|evacua|inunda|subindo|chuva forte|chuvas fortes|atualiz\w* (o|seu) (app|aplicativo|dispositivo))")


def cortar(texto: str, limite: int) -> str:
    texto = " ".join(str(texto).split())
    if len(texto) <= limite:
        return texto
    trecho = texto[:limite]
    fim = max(trecho.rfind(". "), trecho.rfind("! "), trecho.rfind("? "))
    if fim >= limite * 0.5:
        return trecho[:fim + 1]
    return trecho[:trecho.rfind(" ")].rstrip(",;:") + "…"


def _prompt_usuario(evento: dict, base: dict) -> str:
    return json.dumps({"fato": base["mensagem_cidadao"], "dado_foi_exposto": evento["decisao"] == "VAZOU",
                       "acoes_sugeridas": base["o_que_fazer"]}, ensure_ascii=False)


def _validar(texto: str, base: dict | None = None, evento: dict | None = None) -> dict:
    m = re.search(r"\{.*\}", texto or "", re.S)
    if not m:
        raise ValueError("resposta do LLM sem objeto JSON")
    dados = json.loads(m.group(0))
    if isinstance(dados, dict) and "mensagem_cidadao" not in dados:
        dados = next((v for v in dados.values() if isinstance(v, dict) and "mensagem_cidadao" in v), dados)
    if not isinstance(dados, dict) or not str(dados.get("mensagem_cidadao", "")).strip():
        raise ValueError("resposta do LLM sem mensagem_cidadao")
    base = base or {}
    titulo = cortar(motor().mascarar(str(dados.get("titulo") or base.get("titulo", ""))), 60)
    if not titulo.strip() or re.search(r"(?i)chuva|^\s*alerta", titulo):
        titulo = base.get("titulo", titulo)
    msg = cortar(motor().mascarar(str(dados["mensagem_cidadao"])), 260)
    acoes = dados.get("o_que_fazer") or base.get("o_que_fazer", [])
    acoes = [cortar(motor().mascarar(str(x)), 120) for x in (acoes if isinstance(acoes, list) else [acoes]) if str(x).strip()][:3]
    texto_todo = " ".join([titulo, msg, *acoes])
    if _INVENCAO.search(texto_todo):
        raise ValueError("resposta do LLM inventou fatos")
    if evento is not None and evento["decisao"] != "VAZOU" and _PROIBIDO_SE_PROTEGIDO.search(
            re.sub(r"(?i)\b(nada|nenhum\w*|n[ãa]o|sem|nunca|antes|impedi\w*|evit\w*|bloque\w*|protege\w*|para que)\b"
                   r"[\s,]+([\wÀ-ÿ-]+[\s,]+){0,6}?(expost|vaz|afetad|comprometid)\w*", "", texto_todo)):
        raise ValueError("resposta do LLM contradiz o evento (dado protegido)")
    return {"titulo": titulo, "mensagem_cidadao": msg, "nivel_risco": base.get("nivel_risco", "médio"),
            "o_que_fazer": acoes or base.get("o_que_fazer", []), "o_que_fizemos": base.get("o_que_fizemos", ""),
            "correcao_tecnica": base.get("correcao_tecnica", "")}


def _offline(ev: dict) -> dict:
    p = _evento_para_prompt(ev)
    pesos = {c: v["peso"] for c, v in motor().categorias.items()}
    cats = sorted(p["categorias_expostas"] or ["IDENTIFICACAO"], key=lambda c: -pesos.get(c, 0))
    oque = " e ".join(CAT_PT.get(c, c.lower()) for c in cats[:2])
    plural = len(cats[:2]) > 1
    onde = SINK_PT.get(ev["sink"], "em uma saída do sistema")
    vazou = ev["decisao"] == "VAZOU"
    nivel = NIVEL.get(ev["tipo"], "médio")
    if vazou and ("SAUDE" in cats or ev["tipo"] in ("publico", "http")):
        nivel = "crítico"
    if vazou:
        msg = (f"Encontramos uma falha: {oque} {'ficaram visíveis' if plural else 'ficou visível'} {onde}. "
               "Já corrigimos e estamos acompanhando. Seus alertas de chuva continuam funcionando normalmente.")
        fizemos = "A falha foi registrada e a correção entrou no sistema de proteção."
    else:
        verbo = "bloqueou" if ev["decisao"] == "BLOQUEADO" else "escondeu"
        msg = (f"O sistema de proteção {verbo} {oque} antes de {'aparecerem' if plural else 'aparecer'} {onde}. "
               "Nada foi exposto e seu alerta de chuva chegou normalmente.")
        fizemos = f"O Guardião {verbo} automaticamente o dado antes da saída."
        nivel = "baixo"
    curto = CAT_CURTO.get(cats[0], "Seu dado")
    titulo = (f"{curto} ficou visível {SINK_CURTO.get(ev['sink'], '')}" if vazou
              else f"{curto} {'protegida' if curto.startswith('Sua ') else 'protegido'} {SINK_CURTO.get(ev['sink'], '')}").strip()
    return {"titulo": cortar(titulo, 60), "mensagem_cidadao": cortar(msg, 260), "nivel_risco": nivel,
            "o_que_fazer": [ACOES_CIDADAO.get(c, "") for c in cats[:3] if ACOES_CIDADAO.get(c)],
            "o_que_fizemos": fizemos, "correcao_tecnica": CORRECAO_DEV.get(ev["sink"], "Aplicar mascarar() antes da saída.")}


def provedor_llm() -> tuple[str | None, str]:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic", os.environ.get("ALERTACHUVA_LLM_MODEL", "claude-haiku-5-5")
    if os.environ.get("OLLAMA_MODEL"):
        host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
        try:
            with urllib.request.urlopen(f"{host}/api/tags", timeout=3) as r:
                modelos = [m.get("name", "") for m in json.load(r).get("models", [])]
        except Exception:
            return None, f"Ollama não respondeu em {host} (o app está aberto?)"
        alvo = os.environ["OLLAMA_MODEL"]
        if not any(m == alvo or m.split(":")[0] == alvo.split(":")[0] for m in modelos):
            return None, f"modelo '{alvo}' não encontrado no Ollama (rode: ollama pull {alvo})"
        return "ollama", alvo
    return None, "sem LLM configurado"


class TradutorIA:
    def __init__(self, arquivo_cache: str | os.PathLike | None = None, verboso: bool = False):
        self.verboso = verboso
        self.provedor, self.detalhe = provedor_llm()
        self.arquivo_cache = arquivo_cache
        self._cache: dict[str, dict] = {}
        if arquivo_cache and os.path.exists(arquivo_cache):
            try:
                with open(arquivo_cache, encoding="utf-8") as f:
                    self._cache = {k: v for k, v in json.load(f).items()
                                   if not str(v.get("fonte_ia", "")).startswith(("offline (falha", "offline (LLM descartado"))}
            except ValueError:
                self._cache = {}
        if verboso:
            print(f"  IA: {self.provedor + '/' + self.detalhe if self.provedor else 'modo offline (' + self.detalhe + ')'}")

    def _salvar_cache(self):
        if self.arquivo_cache:
            with open(self.arquivo_cache, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, ensure_ascii=False, indent=1)

    def traduzir(self, evento: dict) -> dict:
        p = _evento_para_prompt(evento)
        chave = "|".join(["v" + PROMPT_VERSAO, self.provedor or "offline", self.detalhe if self.provedor else "", evento["sink"],
                          evento["decisao"], ",".join(p["categorias_expostas"])])
        if chave not in self._cache:
            inicio = time.time()
            falhou = False
            if self.provedor:
                erro = None
                for _ in range(2):
                    try:
                        base = _offline(evento)
                        bruto, fonte = _chamar_llm(PROMPT_SISTEMA, _prompt_usuario(evento, base))
                        saida = _validar(bruto, base, evento)
                        break
                    except Exception as e:
                        erro = e
                else:
                    motivo = str(erro) if isinstance(erro, ValueError) else type(erro).__name__
                    saida, fonte, falhou = _offline(evento), f"offline (LLM descartado: {motivo})", True
            else:
                saida, fonte = _offline(evento), f"offline ({self.detalhe})"
            resultado = {**saida, "fonte_ia": fonte}
            if falhou:
                return {**resultado, "evento": p, "ts": evento["ts"], "fase": evento.get("fase", "")}
            self._cache[chave] = resultado
            self._salvar_cache()
            if self.verboso and self.provedor:
                print(f"    IA traduziu {evento['sink']} / {evento['decisao']} em {time.time() - inicio:.1f}s → {fonte}")
        return {**self._cache[chave], "evento": p, "ts": evento["ts"], "fase": evento.get("fase", "")}
