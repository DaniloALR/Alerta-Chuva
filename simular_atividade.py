from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
sys.path.insert(0, str(RAIZ))

from guardiao.ia_remediacao import TradutorIA
from guardiao.taint import GUARDIAO, REGISTRO
from prototipo import saidas
from prototipo.servico_alerta import ServicoAlerta

OCORRENCIAS = [
    ("M-0003", "Meu vizinho Seu Zé, CPF 390.533.447-05, é cadeirante e está ilhado na Rua Beira-Rio, 45. Liga (11) 97777-1234"),
    ("M-0007", "Água entrando nas casas da Viela das Taboas, já passou do joelho"),
    ("M-0011", "Dona Cida é acamada e mora sozinha na Rua da Várzea, 210, alguém ajuda? zap 11 96543-2109"),
    ("M-0015", "Bueiro entupido na esquina, rua alagando rápido"),
    ("M-0019", "minha senha=Chuva@4321 não funciona no app, meu email é joana.teste@exemplo.com.br"),
]
CADASTROS = [
    {"nome": "Morador Teste A", "cpf": "529.982.247-25", "telefone": "(11) 98765-4321", "senha": "Chuva@1234",
     "endereco": "Rua das Garças, 77", "cep": "08062-120", "condicao_saude": "gestante"},
    {"nome": "Morador Teste B", "cpf": "168.995.350-09", "telefone": "11 91234-5678", "senha": "Pantanal#99",
     "endereco": "Rua Lagoa Azul, 310", "data_nascimento": "14/02/1951"},
]


def roteiro(s: ServicoAlerta, rnd: random.Random):
    yield "cadastro de morador pelo app", lambda: s.cadastrar_morador(CADASTROS[0])
    yield "previsão do modelo de ML: risco ALTO → SMS para área de risco", lambda: s.emitir_alerta("ALTO", 42)
    yield "ocorrência enviada por morador", lambda: s.registrar_ocorrencia(*OCORRENCIAS[0], -23.4912345, -46.4312345)
    yield "sensor ESP32 sem conexão com o broker", lambda: s.ingerir_leitura_sensor({"sensor": "ESP32-PANTANAL-01", "nivel_cm": None})
    yield "equipe publica lista de prioridade no canal do bairro", s.publicar_lista_prioridade
    yield "ocorrência enviada por morador", lambda: s.registrar_ocorrencia(*OCORRENCIAS[1], -23.4931, -46.4302)
    yield "consulta à API por terceiro (sem ser o titular)", lambda: s.consultar_morador("M-0002", "M-0009")
    yield "consulta à API pelo próprio titular", lambda: s.consultar_morador("M-0004", "M-0004")
    yield "exportação para a Defesa Civil", s.exportar_defesa_civil
    yield "ocorrência enviada por morador", lambda: s.registrar_ocorrencia(*OCORRENCIAS[2], -23.4899871, -46.4288810)
    yield "novo cadastro", lambda: s.cadastrar_morador(CADASTROS[1])
    yield "leitura normal do sensor", lambda: s.ingerir_leitura_sensor({"sensor": "ESP32-PANTANAL-01", "nivel_cm": rnd.randint(30, 80)})
    yield "ocorrência enviada por morador", lambda: s.registrar_ocorrencia(*OCORRENCIAS[3], -23.4920, -46.4310)
    yield "ocorrência enviada por morador", lambda: s.registrar_ocorrencia(*OCORRENCIAS[4], -23.4911, -46.4333)


def executar(saida: Path, ao_vivo: bool = False, pausa: float = 1.2):
    saida.mkdir(parents=True, exist_ok=True)
    auditoria, alertas = saida / "auditoria.jsonl", saida / "alertas_ia.jsonl"
    for f in (auditoria, alertas):
        f.unlink(missing_ok=True)
    tradutor = TradutorIA(RAIZ / "cache_ia.json", verboso=True)
    vistos = set()

    def ao_evento(ev):
        if ev["decisao"] in ("LIMPO", "PERMITIDO"):
            return
        chave = (ev["fase"], ev["sink"], ev["decisao"], tuple(sorted({a["categoria"] for a in ev["achados"] if a["violacao"]})))
        if chave in vistos:
            return
        vistos.add(chave)
        with open(alertas, "a", encoding="utf-8") as f:
            f.write(json.dumps(tradutor.traduzir(ev), ensure_ascii=False) + "\n")

    GUARDIAO.ouvintes = [ao_evento]
    GUARDIAO.configurar(arquivo_auditoria=auditoria)
    fases = [("monitorar", "1-ANTES (sem Guardião)", "antes"), ("proteger", "2-DEPOIS (Guardião ativo)", "depois")]
    for modo, fase, pasta in fases:
        REGISTRO.limpar()
        GUARDIAO.configurar(modo=modo, fase=fase)
        saidas.PASTA = saida / "saidas" / pasta
        if saidas.PASTA.exists():
            for f in saidas.PASTA.iterdir():
                f.unlink()
        s = ServicoAlerta()
        print(f"\n=== {fase} ===")
        for desc, acao in roteiro(s, random.Random(7)):
            antes = sum(1 for _ in open(auditoria, encoding="utf-8")) if auditoria.exists() else 0
            acao()
            depois = sum(1 for _ in open(auditoria, encoding="utf-8")) if auditoria.exists() else 0
            print(f"  • {desc:<62} eventos de auditoria: +{depois - antes}")
            if ao_vivo:
                time.sleep(pausa)
        if ao_vivo:
            time.sleep(pausa * 3)
    print(f"\nAuditoria: {auditoria}\nAlertas IA: {alertas}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ao-vivo", action="store_true")
    ap.add_argument("--pausa", type=float, default=1.2)
    ap.add_argument("--saida", default=str(RAIZ / "evidencias"))
    a = ap.parse_args()
    executar(Path(a.saida), a.ao_vivo, a.pausa)
