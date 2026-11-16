from __future__ import annotations

import functools
import inspect
import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from .pii_engine import impressao, motor, so_digitos

EXPOSICAO = {"publico": 1.0, "terceiro": 0.9, "exportacao": 0.8, "http": 0.8, "log": 0.5, "titular": 0.3}


class Rotulo(NamedTuple):
    categoria: str
    origem: str
    titular: str | None = None


class ViolacaoTaint(PermissionError):
    def __init__(self, evento: dict):
        self.evento = evento
        cats = sorted({a["categoria"] for a in evento["achados"] if a["violacao"]})
        super().__init__(f"[Guardião] saída '{evento['sink']}' bloqueada: {', '.join(cats)}")


def _rot(x) -> frozenset:
    return getattr(x, "rotulos", frozenset())


class TStr(str):

    def __new__(cls, valor, rotulos=frozenset(), trilha=()):
        o = super().__new__(cls, valor)
        o.rotulos = frozenset(rotulos)
        o.trilha = tuple(trilha)[-10:]
        return o

    def _novo(self, res, op, outro=None):
        rot = self.rotulos | _rot(outro)
        if isinstance(res, str) and rot:
            return TStr(res, rot, self.trilha + (op,))
        return res

    def __add__(self, o): return self._novo(str.__add__(self, o), "concat", o)
    def __radd__(self, o): return self._novo(str.__add__(o, self), "concat", o)
    def __mod__(self, o): return self._novo(str.__mod__(self, o), "%", o)
    def __rmod__(self, o): return self._novo(str.__mod__(o, self), "%", o)
    def __getitem__(self, k): return self._novo(str.__getitem__(self, k), "fatia")
    def __format__(self, spec): return self._novo(str.__format__(self, spec), "format")
    def __reduce__(self): return (TStr, (str(self), self.rotulos, self.trilha))

    def format(self, *a, **k):
        rot = self.rotulos.union(*(_rot(x) for x in (*a, *k.values())))
        return TStr(str.format(self, *a, **k), rot, self.trilha + (".format",))

    def split(self, *a, **k):
        return [TStr(p, self.rotulos, self.trilha + ("split",)) for p in str.split(self, *a, **k)]


for _m in ("upper", "lower", "strip", "lstrip", "rstrip", "title", "capitalize", "casefold", "replace",
           "zfill", "center", "ljust", "rjust", "removeprefix", "removesuffix"):
    def _mk(nome):
        def f(self, *a, **k):
            return self._novo(getattr(str, nome)(self, *a, **k), nome)
        return f
    setattr(TStr, _m, _mk(_m))


def _trilha(origem: str, ops: tuple) -> str:
    comp = []
    for op in ops:
        if comp and comp[-1][0] == op:
            comp[-1][1] += 1
        else:
            comp.append([op, 1])
    return " → ".join([origem] + [f"{o}×{n}" if n > 1 else o for o, n in comp] + ["SINK"])


def tjoin(sep: str, itens) -> str:
    itens = list(itens)
    rot = frozenset().union(*(_rot(i) for i in itens)) | _rot(sep)
    res = str(sep).join(map(str, itens))
    return TStr(res, rot, ("join",)) if rot else res


class _Registro:

    def __init__(self):
        self._itens: dict[str, dict] = {}
        self._lock = threading.Lock()

    def add(self, valor: str, rotulos: frozenset):
        v = str(valor).strip()
        if len(v) < 5:
            return
        with self._lock:
            ant = self._itens.get(v)
            self._itens[v] = {"digitos": so_digitos(v), "masc": _mascara_categoria(v, rotulos), "imp": impressao(v),
                              "rot": (ant["rot"] if ant else frozenset()) | rotulos}

    def procurar(self, texto: str) -> list[dict]:
        dig = so_digitos(texto)
        with self._lock:
            itens = list(self._itens.items())
        achou = []
        for v, d in itens:
            if v in texto:
                achou.append({"valor": v, **d, "pos": [(m.start(), m.end()) for m in re.finditer(re.escape(v), texto)]})
            elif len(d["digitos"]) >= 8 and len(d["digitos"]) >= 0.6 * len(v) and d["digitos"] in dig:
                achou.append({"valor": v, **d, "pos": []})
        return achou

    def limpar(self):
        with self._lock:
            self._itens.clear()


REGISTRO = _Registro()


def _mascara_categoria(valor: str, rotulos) -> str:
    m = motor().mascarar(valor)
    if m != valor:
        return m
    cats = sorted({r.categoria for r in rotulos})
    return f"[{'/'.join(cats) or 'DADO PESSOAL'} OMITIDO]"


def contaminar(valor, categoria: str, origem: str, titular: str | None = None) -> TStr:
    if valor is None:
        return valor
    rot = frozenset({Rotulo(categoria, origem, titular)}) | _rot(valor)
    t = TStr(str(valor), rot, ())
    REGISTRO.add(str(valor), rot)
    return t


def contaminar_registro(dados: dict, origem: str, titular: str | None = None) -> dict:
    m = motor()
    out = {}
    for k, v in dados.items():
        rid = m.chaves.get(str(k).lower())
        if rid and v not in (None, ""):
            out[k] = contaminar(v, m.por_id[rid]["categoria"], f"{origem}.{k}", titular)
        else:
            out[k] = v
    return out


def mascarar(valor) -> str:
    if valor is None:
        return valor
    return _mascara_categoria(str(valor), _rot(valor))


def pseudonimizar(valor) -> str:
    return "PSEUDO-" + impressao(str(valor))[:10]


@dataclass
class Politica:
    nome: str
    tipo: str
    acao: str = "bloquear"
    permitidas: frozenset = frozenset()
    ao_titular: frozenset = frozenset()
    exposicao: float = field(default=0.0)

    def __post_init__(self):
        self.exposicao = self.exposicao or EXPOSICAO.get(self.tipo, 0.5)


class Guardiao:
    def __init__(self):
        self.modo = "proteger"
        self.fase = ""
        self.arquivo_auditoria: Path | None = None
        self.ouvintes = []
        self._lock = threading.Lock()

    def configurar(self, modo=None, fase=None, arquivo_auditoria=None):
        if modo:
            assert modo in ("monitorar", "proteger")
            self.modo = modo
        if fase is not None:
            self.fase = fase
        if arquivo_auditoria:
            self.arquivo_auditoria = Path(arquivo_auditoria)
            self.arquivo_auditoria.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _textos(obj, cam="arg", prof=0):
        if prof > 6:
            return
        if isinstance(obj, str):
            yield cam, obj
        elif isinstance(obj, dict):
            for k, v in obj.items():
                yield from Guardiao._textos(v, f"{cam}.{k}", prof + 1)
        elif isinstance(obj, (list, tuple, set)):
            for i, v in enumerate(obj):
                yield from Guardiao._textos(v, f"{cam}[{i}]", prof + 1)
        elif hasattr(obj, "__dict__") and not callable(obj):
            yield from Guardiao._textos(vars(obj), cam, prof + 1)
        elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
            yield cam, str(obj)

    @staticmethod
    def _liberado(pol: Politica, categoria: str, dono, titular) -> bool:
        return categoria in pol.permitidas or (categoria in pol.ao_titular and titular is not None and dono == titular)

    def _achados(self, pol: Politica, args, kwargs, titular):
        achados = []
        for cam, txt in self._textos({"args": list(args), "kwargs": kwargs}, "$"):
            if cam.endswith(".titular"):
                continue
            ja = set()
            for r in _rot(txt):
                ja.add(r)
                achados.append({"camada": "1-rótulo propagado", "categoria": r.categoria, "origem": r.origem,
                                "titular": r.titular, "caminho": cam, "trilha": _trilha(r.origem, txt.trilha),
                                "valor_mascarado": None})
            ocorr = REGISTRO.procurar(str(txt))
            for o in ocorr:
                for r in o["rot"] - ja:
                    ja.add(r)
                    achados.append({"camada": "2-valor contaminado", "categoria": r.categoria, "origem": r.origem,
                                    "titular": r.titular, "caminho": cam,
                                    "trilha": "rótulo perdido (f-string/str/reformatação), valor reconhecido",
                                    "valor_mascarado": o["masc"]})
            imps = {o["imp"] for o in ocorr}
            spans = [p for o in ocorr for p in o["pos"]]
            for a in motor().analisar(str(txt), cam):
                if a.impressao in imps or any(a.inicio < f and a.fim > i for i, f in spans):
                    continue
                achados.append({"camada": "3-conteúdo (motor PII)", "categoria": a.categoria, "origem": "não rastreada",
                                "titular": None, "caminho": cam, "trilha": f"regra {a.regra} ({a.codificacao})",
                                "valor_mascarado": a.valor_mascarado, "regra": a.regra})
        for a in achados:
            a["violacao"] = not self._liberado(pol, a["categoria"], a["titular"], titular)
        return achados

    @staticmethod
    def _local():
        for fr in inspect.stack()[3:]:
            if "/guardiao/" not in fr.filename.replace("\\", "/"):
                return f"{Path(fr.filename).name}:{fr.lineno} em {fr.function}()"
        return "?"

    def _sanitizar_obj(self, obj, pol: Politica, titular):
        if isinstance(obj, str):
            s, guardados = str(obj), []
            for o in sorted(REGISTRO.procurar(s), key=lambda x: -len(x["valor"])):
                if not o["pos"]:
                    continue
                if all(self._liberado(pol, r.categoria, r.titular, titular) for r in o["rot"]):
                    guardados.append(o["valor"])
                    s = s.replace(o["valor"], f"\ue000{len(guardados) - 1}\ue001")
                else:
                    s = s.replace(o["valor"], o["masc"])
            s = motor().mascarar(s, manter=pol.permitidas)
            for i, v in enumerate(guardados):
                s = s.replace(f"\ue000{i}\ue001", v)
            return s
        if isinstance(obj, dict):
            return {k: self._sanitizar_obj(v, pol, titular) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return type(obj)(self._sanitizar_obj(v, pol, titular) for v in obj)
        if hasattr(obj, "__dict__") and not callable(obj):
            return {k: self._sanitizar_obj(v, pol, titular) for k, v in vars(obj).items()}
        return obj

    def processar(self, pol: Politica, fn, args, kwargs, titular):
        achados = self._achados(pol, args, kwargs, titular)
        viol = [a for a in achados if a["violacao"]]
        if not achados:
            decisao = "LIMPO"
        elif not viol:
            decisao = "PERMITIDO"
        elif self.modo == "monitorar":
            decisao = "VAZOU"
        else:
            decisao = "BLOQUEADO" if pol.acao == "bloquear" else "MASCARADO"
        evento = {"ts": time.time(), "fase": self.fase, "modo": self.modo, "sink": pol.nome, "tipo": pol.tipo,
                  "exposicao": pol.exposicao, "acao_politica": pol.acao, "decisao": decisao, "local": self._local(),
                  "titulares": sorted({a["titular"] for a in viol if a["titular"]}), "achados": achados}
        if decisao != "LIMPO":
            self._registrar(evento)
        if decisao == "BLOQUEADO":
            raise ViolacaoTaint(evento)
        if decisao == "MASCARADO":
            args = self._sanitizar_obj(list(args), pol, titular)
            kwargs = {k: (v if k == "titular" else self._sanitizar_obj(v, pol, titular)) for k, v in kwargs.items()}
        return fn(*args, **kwargs)

    def _registrar(self, evento):
        with self._lock:
            if self.arquivo_auditoria:
                with open(self.arquivo_auditoria, "a", encoding="utf-8") as f:
                    f.write(json.dumps(evento, ensure_ascii=False, default=str) + "\n")
        for cb in self.ouvintes:
            cb(evento)


GUARDIAO = Guardiao()


def sink(nome: str, tipo: str, acao: str = "bloquear", permitidas=(), ao_titular=(), exposicao: float = 0.0):
    pol = Politica(nome, tipo, acao, frozenset(permitidas), frozenset(ao_titular), exposicao)

    def deco(fn):
        @functools.wraps(fn)
        def w(*args, titular=None, **kwargs):
            if "titular" in inspect.signature(fn).parameters:
                kwargs["titular"] = titular
            return GUARDIAO.processar(pol, fn, args, kwargs, titular)
        w.politica = pol
        return w
    return deco
