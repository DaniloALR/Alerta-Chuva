from __future__ import annotations

from collections import Counter, defaultdict

from .pii_engine import motor

FATOR = {"VAZOU": 1.0, "MASCARADO": 0.05, "BLOQUEADO": 0.0}
FAIXAS = [(15, "BAIXO", "#0ca30c"), (40, "MODERADO", "#fab219"), (70, "ALTO", "#ec835a"), (101, "CRÍTICO", "#d03b3b")]


def nivel(indice: float) -> tuple[str, str]:
    for lim, nome, cor in FAIXAS:
        if indice < lim:
            return nome, cor
    return FAIXAS[-1][1], FAIXAS[-1][2]


def _pontos(ev: dict, pesos: dict):
    pot = real = 0.0
    for a in ev["achados"]:
        if not a["violacao"]:
            continue
        p = pesos.get(a["categoria"], 5) * ev["exposicao"]
        pot += p
        real += p * FATOR.get(ev["decisao"], 0)
    return pot, real


def calcular(eventos: list[dict], janela: int = 20) -> dict:
    pesos = {c: v["peso"] for c, v in motor().categorias.items()}
    pot = real = 0.0
    por_cat = defaultdict(lambda: {"potencial": 0.0, "real": 0.0, "ocorrencias": 0})
    por_sink = defaultdict(Counter)
    expostos, protegidos = set(), set()
    serie, buf = [], []
    for i, ev in enumerate(eventos):
        p, r = _pontos(ev, pesos)
        pot, real = pot + p, real + r
        buf = (buf + [(p, r)])[-janela:]
        sp = sum(x for x, _ in buf)
        serie.append({"i": i + 1, "ts": ev["ts"], "fase": ev.get("fase", ""),
                      "indice": round(100 * sum(y for _, y in buf) / sp, 1) if sp else 0.0})
        por_sink[ev["sink"]][ev["decisao"]] += 1
        for a in ev["achados"]:
            if a["violacao"]:
                c = por_cat[a["categoria"]]
                c["ocorrencias"] += 1
                c["potencial"] += pesos.get(a["categoria"], 5) * ev["exposicao"]
                c["real"] += pesos.get(a["categoria"], 5) * ev["exposicao"] * FATOR.get(ev["decisao"], 0)
        alvo = expostos if ev["decisao"] == "VAZOU" else protegidos if ev["decisao"] in ("BLOQUEADO", "MASCARADO") else None
        if alvo is not None:
            alvo.update(ev.get("titulares", []))
    indice_atual = serie[-1]["indice"] if serie else 0.0
    nome, cor = nivel(indice_atual)
    decisoes = Counter(e["decisao"] for e in eventos)
    camadas = Counter(a["camada"] for e in eventos for a in e["achados"] if a["violacao"])
    return {
        "indice_atual": indice_atual, "nivel": nome, "cor": cor,
        "indice_acumulado": round(100 * real / pot, 1) if pot else 0.0,
        "eventos": len(eventos), "decisoes": dict(decisoes), "camadas": dict(camadas),
        "moradores_expostos": len(expostos), "moradores_protegidos": len(protegidos - expostos),
        "por_categoria": {k: {**v, "potencial": round(v["potencial"], 1), "real": round(v["real"], 1)}
                          for k, v in sorted(por_cat.items(), key=lambda kv: -kv[1]["potencial"])},
        "por_sink": {k: dict(v) for k, v in por_sink.items()}, "serie": serie, "janela": janela}


def por_fase(eventos: list[dict]) -> dict:
    fases = defaultdict(list)
    for e in eventos:
        fases[e.get("fase", "")].append(e)
    out = {}
    for f, evs in fases.items():
        r = calcular(evs, janela=len(evs) or 1)
        out[f] = {k: r[k] for k in ("indice_acumulado", "eventos", "decisoes", "moradores_expostos",
                                    "moradores_protegidos", "por_categoria", "camadas")}
        out[f]["nivel"] = nivel(r["indice_acumulado"])[0]
    return out
