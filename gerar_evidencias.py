from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
sys.path.insert(0, str(RAIZ))
EVID = RAIZ / "evidencias"

from guardiao.analise_estatica import analisar_arquivo, relatorio_markdown
from guardiao.pii_engine import motor

CORPUS = [
    "Morador CPF 529.982.247-25 pediu ajuda",
    "cpf ５２９９８２２４７２５ (dígitos Unicode fullwidth)",
    "cpf 529​.982.247-25 (caractere invisível no meio)",
    "cpf%3A%20529.982.247-25 (URL-encoded)",
    "payload=eyJjcGYiOiAiNTI5Ljk4Mi4yNDctMjUifQ== (Base64)",
    "protocolo 11111111111 (falso positivo evitado)",
    "nota fiscal 52998224726 (dígito verificador inválido)",
    "Dona Ana é cadeirante e insulino-dependente",
    "laudo CID F32.1, cartão SUS 898 0012 3456 7891",
    "erro: postgres://admin:S3nh4Forte@db.local:5432/alerta",
    '{"usuario": "ana", "password": "Chuva@2026"}',
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJlc3AzMiJ9.c2lnbmF0dXJh",
    "Zap (11) 98765-4321 · e-mail ana.souza@exemplo.com.br",
    "Mora na Rua Beira-Rio, 45, CEP 08061-300",
    "Ocorrência em -23.4912345, -46.4312345",
    "nascimento 12/03/1951",
    "evento em 12/03/2024 (data sem contexto: ignorada)",
]


def passo(t):
    print(f"\n▶ {t}")


def main():
    if EVID.exists():
        shutil.rmtree(EVID)
    EVID.mkdir()

    passo("1/6 Testes automatizados")
    env = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "OLLAMA_MODEL", "OLLAMA_HOST")}
    env.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"})
    r = subprocess.run([sys.executable, "-m", "pytest", "-v", "--no-header", "-p", "no:cacheprovider", "tests/"],
                       cwd=RAIZ, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=300)
    saida = (r.stdout or "") + (r.stderr or "")
    (EVID / "01_testes_pytest.txt").write_text(saida, encoding="utf-8")
    if "No module named pytest" in saida:
        print("pytest não instalado: rode 'python -m pip install pytest' e execute de novo para gerar 01_testes_pytest.txt")
    else:
        linhas = saida.strip().splitlines()
        print(linhas[-1] if linhas else "pytest não produziu saída")

    passo("2/6 Demonstração do motor de parsing PII")
    m = motor()
    linhas = [f"# Motor de parsing PII: demonstração (regras v{m.versao}, {len(m.regras)} regras)", "",
              "| Entrada (sintética) | Regras disparadas | Saída mascarada |", "|---|---|---|"]
    for t in CORPUS:
        ach = m.analisar(t)
        reg = ", ".join(f"{a.regra} ({a.confianca:.2f}{', ' + a.codificacao if a.codificacao != 'texto' else ''})" for a in ach) or "nenhuma"
        linhas.append(f"| `{t}` | {reg} | `{m.mascarar(t)}` |")
    linhas += ["", "## Regras configuradas", "", "| ID | Categoria | Peso | Validador | Contexto obrigatório | Descrição |", "|---|---|---|---|---|---|"]
    for rg in m.regras:
        linhas.append(f"| {rg['id']} | {rg['categoria']} | {rg['peso']} | {rg.get('validador', '-')} | "
                      f"{'sim' if rg.get('requer_contexto') else 'só 8 dígitos' if rg.get('requer_contexto_se') else 'não'} | {rg['descricao']} |")
    (EVID / "01_motor_pii_demo.md").write_text("\n".join(linhas) + "\n", encoding="utf-8")

    passo("3/6 Taint Analysis estático (SAST)")
    fl = analisar_arquivo(RAIZ / "prototipo" / "servico_alerta.py")
    (EVID / "02_taint_estatico.md").write_text(relatorio_markdown(fl, "prototipo/servico_alerta.py"), encoding="utf-8")
    (EVID / "02_taint_estatico.json").write_text(json.dumps([asdict(f) for f in fl], ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{len(fl)} fluxos analisados")

    passo("4/6 Auditoria dinâmica: antes × depois (+ tradução via IA)")
    import simular_atividade
    simular_atividade.executar(EVID)

    passo("5/6 Relatório consolidado")
    from guardiao.risco import calcular, por_fase
    ev = [json.loads(l) for l in (EVID / "auditoria.jsonl").read_text(encoding="utf-8").splitlines()]
    alertas = [json.loads(l) for l in (EVID / "alertas_ia.jsonl").read_text(encoding="utf-8").splitlines()]
    pf = por_fase(ev)
    rel = ["# Auditoria do protótipo AlertaChuva: Taint Analysis em ação", "",
           "Mesmo código e mesmo roteiro de uso (um dia de chuva forte: cadastro, alerta por SMS, ocorrências, sensor ESP32, "
           "API, Defesa Civil), executado duas vezes: **sem** e **com** o Guardião.", "",
           "| Indicador | Antes (sem Guardião) | Depois (Guardião ativo) |", "|---|---|---|"]
    A, D = pf["1-ANTES (sem Guardião)"], pf["2-DEPOIS (Guardião ativo)"]
    for nome, f in [("**Risco Cidadão (0–100)**", lambda x: f"**{x['indice_acumulado']} ({x['nivel']})**"),
                    ("Saídas com dado pessoal auditadas", lambda x: x["eventos"]),
                    ("Vazamentos", lambda x: x["decisoes"].get("VAZOU", 0)),
                    ("Bloqueados", lambda x: x["decisoes"].get("BLOQUEADO", 0)),
                    ("Mascarados", lambda x: x["decisoes"].get("MASCARADO", 0)),
                    ("Permitidos pela política (base legal)", lambda x: x["decisoes"].get("PERMITIDO", 0)),
                    ("Moradores com dado exposto", lambda x: x["moradores_expostos"]),
                    ("Moradores protegidos", lambda x: x["moradores_protegidos"])]:
        rel.append(f"| {nome} | {f(A)} | {f(D)} |")
    rel += ["", "## Detecção por camada (achados em saídas proibidas)", "", "| Camada | Achados |", "|---|---|"]
    for c, n in sorted(calcular(ev)["camadas"].items()):
        rel.append(f"| {c} | {n} |")
    rel += ["", "## Decisões por saída (sink), fase DEPOIS", "", "| Saída | Política | Decisões |", "|---|---|---|"]
    vis = {}
    for e in ev:
        if e["fase"].startswith("2"):
            vis.setdefault(e["sink"], [e["acao_politica"], {}])[1][e["decisao"]] = vis.get(e["sink"], [0, {}])[1].get(e["decisao"], 0) + 1
    for s, (pol, dec) in vis.items():
        rel.append(f"| `{s}` | {pol} | {', '.join(f'{k}: {v}' for k, v in dec.items())} |")
    rel += ["", "## Exemplos de trilha (fonte → transformações → saída)", ""]
    vistos = set()
    for e in ev:
        if not e["fase"].startswith("2"):
            continue
        for a in e["achados"]:
            k = (e["sink"], a["camada"])
            if a["violacao"] and k not in vistos and len(vistos) < 8:
                vistos.add(k)
                rel.append(f"- **{e['decisao']}** em `{e['sink']}` ({e['local']}): {a['categoria']} · camada *{a['camada']}* · `{a['trilha']}`")
    rel += ["", "## O que efetivamente saiu do sistema (primeira linha de cada saída)", ""]
    for arq in ["sms_enviados.log", "canal_publico.log", "mapa_publico.jsonl", "llm_prompts.log", "app.log", "defesa_civil_export.jsonl"]:
        rel.append(f"**{arq}**")
        for fase in ("antes", "depois"):
            p = EVID / "saidas" / fase / arq
            linha = p.read_text(encoding="utf-8").splitlines()[0] if p.exists() else "(nada)"
            if arq == "canal_publico.log" and p.exists():
                ls = p.read_text(encoding="utf-8").splitlines()
                linha = next((l for l in ls if "rioridade" in l or "famílias" in l), ls[0])
            rel.append(f"- {fase.upper()}: `{linha[:260]}{'…' if len(linha) > 260 else ''}`")
        rel.append("")
    rel += ["## Alertas ao cidadão gerados pela IA (amostra da fase DEPOIS)", ""]
    for a in [x for x in alertas if x["fase"].startswith("2")][:4]:
        rel.append(f"- **{a['titulo']}** ({a['evento']['saida']}, risco {a['nivel_risco']}): {a['mensagem_cidadao']}  \n"
                   f"  *Correção p/ equipe:* {a['correcao_tecnica']}  *Fonte:* {a['fonte_ia']}")
    rel += ["", "> Dados de moradores 100% sintéticos. O arquivo `auditoria.jsonl` não contém nenhum valor pessoal: só categoria, "
            "origem, local do código e valor já mascarado (ver teste `test_auditoria_nao_contem_pii`)."]
    (EVID / "03_relatorio_auditoria.md").write_text("\n".join(rel) + "\n", encoding="utf-8")
    print(f"ANTES {A['indice_acumulado']} ({A['nivel']}) → DEPOIS {D['indice_acumulado']} ({D['nivel']})")

    passo("6/6 Dashboard executivo (snapshot + print)")
    from dashboard.server import estado
    html = (RAIZ / "dashboard" / "index.html").read_text(encoding="utf-8")
    dados = json.dumps(estado(), ensure_ascii=False).replace("</", "<\\/")
    snap = EVID / "04_dashboard_snapshot.html"
    snap.write_text(html.replace("<script>\nconst $=", f"<script>window.__ESTADO__={dados};</script>\n<script>\nconst $=", 1), encoding="utf-8")
    candidatos = [shutil.which(n) for n in ("google-chrome", "chromium", "chromium-browser", "chrome", "msedge")]
    for base in (os.environ.get("PROGRAMFILES", ""), os.environ.get("PROGRAMFILES(X86)", ""), os.environ.get("LOCALAPPDATA", "")):
        candidatos += [os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"),
                       os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe")]
    candidatos += ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                   "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"]
    for nav in candidatos:
        if nav and os.path.isfile(nav):
            subprocess.run([nav, "--headless=new", "--disable-gpu", "--no-sandbox", "--hide-scrollbars", "--window-size=1440,2050",
                            f"--screenshot={EVID / '04_dashboard_risco_cidadao.png'}", snap.as_uri()], capture_output=True, timeout=90)
            break
    print("ok" if (EVID / "04_dashboard_risco_cidadao.png").exists() else "PNG não gerado (sem Chrome): abra o snapshot e tire o print")


if __name__ == "__main__":
    main()
