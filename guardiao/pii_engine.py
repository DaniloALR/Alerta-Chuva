from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import unicodedata
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import parse_qsl, unquote_plus

REGRAS_PADRAO = Path(__file__).with_name("regras_pii.json")
_SEGREDO = os.environ.get("ALERTACHUVA_PII_SALT", "troque-este-segredo-em-producao").encode()
_INVISIVEIS = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
_HIFENS = dict.fromkeys(map(ord, "‐‑‒–—−"), "-")
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_DDD = {11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 24, 27, 28, 31, 32, 33, 34, 35, 37, 38, 41, 42, 43, 44, 45, 46,
        47, 48, 49, 51, 53, 54, 55, 61, 62, 63, 64, 65, 66, 67, 68, 69, 71, 73, 74, 75, 77, 79, 81, 82, 83, 84, 85,
        86, 87, 88, 89, 91, 92, 93, 94, 95, 96, 97, 98, 99}


def so_digitos(s: str) -> str:
    return re.sub(r"\D", "", s)


def _cpf(v: str) -> bool:
    d = so_digitos(v)
    if len(d) != 11 or d == d[0] * 11:
        return False
    for n in (9, 10):
        s = sum(int(d[i]) * (n + 1 - i) for i in range(n))
        if int(d[n]) != (s * 10 % 11) % 10:
            return False
    return True


def _cns(v: str) -> bool:
    d = so_digitos(v)
    return len(d) == 15 and d[0] in "12789" and sum(int(c) * (15 - i) for i, c in enumerate(d)) % 11 == 0


def _luhn(v: str) -> bool:
    d = so_digitos(v)
    if not 13 <= len(d) <= 19 or d == d[0] * len(d):
        return False
    tot = 0
    for i, c in enumerate(reversed(d)):
        n = int(c) * (2 if i % 2 else 1)
        tot += n - 9 if n > 9 else n
    return tot % 10 == 0


def _telefone(v: str) -> bool:
    d = so_digitos(v)
    if len(d) in (12, 13) and d.startswith("55"):
        d = d[2:]
    if len(d) not in (10, 11) or int(d[:2]) not in _DDD:
        return False
    return d[2] == "9" if len(d) == 11 else d[2] in "2345"


VALIDADORES = {"cpf": _cpf, "cns": _cns, "luhn": _luhn, "telefone": _telefone}


def _m_cpf(v): return "***.***.***-" + so_digitos(v)[-2:]
def _m_tel(v):
    d = so_digitos(v)
    d = d[2:] if len(d) in (12, 13) and d.startswith("55") else d
    return f"({d[:2]}) *****-{d[-4:]}"
def _m_email(v): u, _, dom = v.partition("@"); return f"{u[:1]}***@{dom}"
def _m_cartao(v): return "**** **** **** " + so_digitos(v)[-4:]
def _m_cep(v): return so_digitos(v)[:2] + "***-***"
def _m_data(v): return "**/**/" + v[-4:]
def _m_cred(v): return re.match(r"(.*?[:=]\s*[\"']?)", v).group(1) + "[SEGREDO REMOVIDO]"
def _m_cred_url(v): return re.sub(r"//[^@]+@", "//***:***@", v)


def _m_geo(v):
    nums = re.findall(r"-?\d+\.\d+", v)
    return ", ".join(f"{float(n):.2f}" for n in nums[:2]) + " (aprox.)"


MASCARAS = {"cpf": _m_cpf, "telefone": _m_tel, "email": _m_email, "cartao": _m_cartao, "cep": _m_cep,
            "data": _m_data, "credencial": _m_cred, "credencial_url": _m_cred_url, "geo": _m_geo,
            "id": lambda v: "[DOCUMENTO OMITIDO]", "saude": lambda v: "[DADO DE SAÚDE]",
            "endereco": lambda v: "[ENDEREÇO OMITIDO]", "segredo": lambda v: "[SEGREDO REMOVIDO]"}


def normalizar(texto: str) -> str:
    t = unicodedata.normalize("NFKC", texto).translate(_INVISIVEIS).translate(_HIFENS)
    if re.search(r"%[0-9A-Fa-f]{2}", t):
        t = unquote_plus(t)
    return t


def impressao(valor: str) -> str:
    canon = so_digitos(valor) if len(so_digitos(valor)) >= 8 else normalizar(valor).lower().strip()
    return hmac.new(_SEGREDO, canon.encode(), hashlib.sha256).hexdigest()[:16]


@dataclass
class Achado:
    regra: str
    categoria: str
    peso: int
    valor_mascarado: str
    confianca: float
    inicio: int
    fim: int
    caminho: str = "$"
    codificacao: str = "texto"
    impressao: str = ""

    def to_dict(self):
        return asdict(self)


class MotorPII:
    def __init__(self, caminho_regras: str | Path = REGRAS_PADRAO):
        cfg = json.loads(Path(caminho_regras).read_text(encoding="utf-8"))
        self.versao = cfg["versao"]
        self.categorias = cfg["categorias"]
        self.chaves = {k.lower(): v for k, v in cfg.get("chaves_sensiveis", {}).items()}
        self.regras = []
        for r in cfg["regras"]:
            r = dict(r)
            r["_re"] = re.compile(r["padrao"])
            r["_ctx"] = re.compile("|".join(map(re.escape, r.get("contexto", []))), re.I) if r.get("contexto") else None
            r["_ctx_se"] = re.compile(r["requer_contexto_se"]) if r.get("requer_contexto_se") else None
            r["peso"] = self.categorias[r["categoria"]]["peso"]
            self.regras.append(r)
        self.por_id = {r["id"]: r for r in self.regras}

    def analisar(self, texto: str, caminho: str = "$", _prof: int = 0) -> list[Achado]:
        if not texto:
            return []
        t = normalizar(str(texto))
        brutos: list[Achado] = []
        for r in self.regras:
            for m in r["_re"].finditer(t):
                valor = m.group(0).strip()
                janela = t[max(0, m.start() - 40): m.end() + 15]
                tem_ctx = bool(r["_ctx"] and r["_ctx"].search(janela))
                if r.get("requer_contexto") and not tem_ctx:
                    continue
                if r["_ctx_se"] and r["_ctx_se"].fullmatch(valor) and not tem_ctx:
                    continue
                conf = 0.6
                if r.get("validador"):
                    if not VALIDADORES[r["validador"]](valor):
                        continue
                    conf = 0.85
                conf = min(0.99, conf + (0.14 if tem_ctx else 0))
                brutos.append(Achado(r["id"], r["categoria"], r["peso"], MASCARAS[r["mascara"]](valor),
                                     round(conf, 2), m.start(), m.end(), caminho, "texto", impressao(valor)))
        achados = self._resolver_sobreposicao(brutos)
        if _prof == 0:
            for m in _B64.finditer(t):
                try:
                    dec = base64.b64decode(m.group(0), validate=True).decode("utf-8")
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    continue
                if sum(c.isprintable() for c in dec) / max(1, len(dec)) < 0.9:
                    continue
                for a in self.analisar(dec, caminho, _prof + 1):
                    a.inicio, a.fim, a.codificacao = m.start(), m.end(), "base64"
                    achados.append(a)
        return achados

    @staticmethod
    def _resolver_sobreposicao(achados: list[Achado]) -> list[Achado]:
        ordem = sorted(achados, key=lambda a: (-a.peso, -a.confianca, -(a.fim - a.inicio)))
        final: list[Achado] = []
        for a in ordem:
            if all(a.fim <= b.inicio or a.inicio >= b.fim for b in final):
                final.append(a)
        return sorted(final, key=lambda a: a.inicio)

    def analisar_estrutura(self, obj, caminho: str = "$") -> list[Achado]:
        if isinstance(obj, dict):
            out = []
            for k, v in obj.items():
                cam = f"{caminho}.{k}"
                regra_chave = self.chaves.get(str(k).lower())
                if regra_chave and v not in (None, "") and not isinstance(v, (dict, list)):
                    r = self.por_id[regra_chave]
                    out.append(Achado(r["id"], r["categoria"], r["peso"], self._mascarar_valor(r, str(v)),
                                      0.95, 0, len(str(v)), cam, "campo", impressao(str(v))))
                else:
                    out += self.analisar_estrutura(v, cam)
            return out
        if isinstance(obj, (list, tuple, set)):
            return [a for i, v in enumerate(obj) for a in self.analisar_estrutura(v, f"{caminho}[{i}]")]
        if isinstance(obj, (bytes, bytearray)):
            obj = obj.decode("utf-8", "replace")
        if isinstance(obj, str):
            s = obj.strip()
            if s[:1] in "{[":
                try:
                    return self.analisar_estrutura(json.loads(s), caminho)
                except ValueError:
                    pass
            if "=" in s and "&" in s and " " not in s:
                return self.analisar_estrutura(dict(parse_qsl(s)), caminho)
            return self.analisar(s, caminho)
        if isinstance(obj, (int, float)) and not isinstance(obj, bool):
            return self.analisar(str(obj), caminho)
        return []

    def _mascarar_valor(self, regra: dict, valor: str) -> str:
        if regra["mascara"] == "credencial" and not re.search(r"[:=]", valor):
            return "[SEGREDO REMOVIDO]"
        try:
            return MASCARAS[regra["mascara"]](valor)
        except Exception:
            return "[DADO PESSOAL OMITIDO]"

    def mascarar(self, texto: str, manter: frozenset = frozenset()) -> str:
        t = normalizar(str(texto))
        achados = sorted((a for a in self.analisar(t) if a.categoria not in manter), key=lambda a: a.inicio, reverse=True)
        feitos = set()
        for a in achados:
            if (a.inicio, a.fim) in feitos:
                continue
            feitos.add((a.inicio, a.fim))
            subst = "[BASE64 COM DADO PESSOAL]" if a.codificacao == "base64" else a.valor_mascarado
            t = t[:a.inicio] + subst + t[a.fim:]
        return t

    def mascarar_estrutura(self, obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                rid = self.chaves.get(str(k).lower())
                if rid and v not in (None, "") and not isinstance(v, (dict, list)):
                    out[k] = self._mascarar_valor(self.por_id[rid], str(v))
                else:
                    out[k] = self.mascarar_estrutura(v)
            return out
        if isinstance(obj, (list, tuple)):
            return [self.mascarar_estrutura(v) for v in obj]
        if isinstance(obj, str):
            return self.mascarar(obj)
        return obj


_motor: MotorPII | None = None


def motor() -> MotorPII:
    global _motor
    if _motor is None:
        _motor = MotorPII()
    return _motor
