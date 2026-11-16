from __future__ import annotations

import json
import sys
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from guardiao.risco import calcular, por_fase

EVID = RAIZ / "evidencias"
HTML = Path(__file__).with_name("index.html")


def _jsonl(p: Path) -> list[dict]:
    if not p.exists():
        return []
    out = []
    for linha in p.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(linha))
        except ValueError:
            pass
    return out


def estado() -> dict:
    ev = _jsonl(EVID / "auditoria.jsonl")
    alertas = _jsonl(EVID / "alertas_ia.jsonl")
    sast_p = EVID / "02_taint_estatico.json"
    sast = dict(Counter(f["status"] for f in json.loads(sast_p.read_text(encoding="utf-8")))) if sast_p.exists() else {}
    ult = []
    for e in reversed(ev[-14:]):
        viol = [a for a in e["achados"] if a["violacao"]] or e["achados"]
        ult.append({"ts": e["ts"], "fase": e.get("fase", ""), "sink": e["sink"], "decisao": e["decisao"], "local": e["local"],
                    "categorias": sorted({a["categoria"] for a in viol}), "camadas": sorted({a["camada"][0] for a in viol})})
    fase_atual = ev[-1].get("fase", "") if ev else ""
    atual = calcular([e for e in ev if e.get("fase", "") == fase_atual])
    return {"gerado_em": time.time(), "modo": ev[-1]["modo"] if ev else "-", "risco": calcular(ev),
            "fase_atual": fase_atual, "risco_fase": {k: atual[k] for k in ("eventos", "decisoes", "moradores_expostos", "moradores_protegidos")},
            "fases": por_fase(ev), "ultimos": ult, "alertas": list(reversed(alertas[-6:])), "sast": sast}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/estado"):
            corpo, tipo = json.dumps(estado(), ensure_ascii=False).encode(), "application/json; charset=utf-8"
        elif self.path in ("/", "/index.html"):
            corpo, tipo = HTML.read_bytes(), "text/html; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(corpo)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    porta = int(sys.argv[1]) if len(sys.argv) > 1 else 8050
    print(f"Dashboard Risco Cidadão em http://127.0.0.1:{porta}  (Ctrl+C para sair)")
    ThreadingHTTPServer(("127.0.0.1", porta), H).serve_forever()
