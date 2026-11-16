from __future__ import annotations

import json
import os
from pathlib import Path

from guardiao.taint import sink

PASTA = Path(os.environ.get("ALERTACHUVA_SAIDAS", Path(__file__).resolve().parents[1] / "evidencias" / "saidas"))


def _gravar(arquivo: str, linha: str):
    PASTA.mkdir(parents=True, exist_ok=True)
    with open(PASTA / arquivo, "a", encoding="utf-8") as f:
        f.write(linha.rstrip() + "\n")


class Log:

    @staticmethod
    @sink("log_aplicacao", tipo="log", acao="mascarar")
    def info(msg: str):
        _gravar("app.log", f"INFO  {msg}")

    @staticmethod
    @sink("log_aplicacao", tipo="log", acao="mascarar")
    def debug(msg: str):
        _gravar("app.log", f"DEBUG {msg}")

    @staticmethod
    @sink("log_aplicacao", tipo="log", acao="mascarar")
    def error(msg: str):
        _gravar("app.log", f"ERROR {msg}")


class GatewaySMS:
    @staticmethod
    @sink("sms_alerta_individual", tipo="titular", acao="mascarar", ao_titular={"LOCALIZACAO", "CONTATO"})
    def enviar(telefone: str, mensagem: str, titular=None):
        _gravar("sms_enviados.log", f"para={telefone} | {mensagem}")


class CanalPublicoBairro:

    @staticmethod
    @sink("canal_publico_bairro", tipo="publico", acao="bloquear")
    def publicar(texto: str):
        _gravar("canal_publico.log", texto)


class MapaOcorrencias:
    @staticmethod
    @sink("mapa_publico_ocorrencias", tipo="publico", acao="mascarar")
    def publicar(ocorrencia: dict):
        _gravar("mapa_publico.jsonl", json.dumps(ocorrencia, ensure_ascii=False))


class DefesaCivil:

    @staticmethod
    @sink("exportacao_defesa_civil", tipo="exportacao", acao="mascarar",
          permitidas={"LOCALIZACAO", "SAUDE", "CONTATO"})
    def exportar(linhas: list[dict]):
        _gravar("defesa_civil_export.jsonl", json.dumps(linhas, ensure_ascii=False))


class APIPublica:
    @staticmethod
    @sink("api_http_resposta", tipo="http", acao="bloquear",
          ao_titular={"IDENTIFICACAO", "CONTATO", "LOCALIZACAO", "SAUDE", "NASCIMENTO"})
    def responder(corpo: dict, titular=None):
        _gravar("http_respostas.jsonl", json.dumps(corpo, ensure_ascii=False, default=str))
        return corpo


class IAExterna:

    @staticmethod
    @sink("llm_externo", tipo="terceiro", acao="mascarar")
    def classificar_ocorrencia(texto: str) -> str:
        _gravar("llm_prompts.log", texto)
        t = texto.lower()
        return "pessoa ilhada" if "ilhad" in t else "alagamento" if "água" in t or "agua" in t else "outros"
