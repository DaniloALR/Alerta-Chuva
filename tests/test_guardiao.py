import base64
import json
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from guardiao.analise_estatica import analisar_arquivo
from guardiao.ia_remediacao import TradutorIA, _validar
from guardiao.pii_engine import motor
from guardiao.risco import calcular
from guardiao.taint import GUARDIAO, REGISTRO, TStr, ViolacaoTaint, contaminar, mascarar, sink, tjoin

M = motor()
CPF = "529.982.247-25"


def regras(texto):
    return {a.regra for a in M.analisar(texto)}


@pytest.mark.parametrize("texto", [
    f"CPF {CPF}", "cpf 52998224725", "cpf ５２９９８２２４７２５", "cpf 529​.982.247-25",
    "cpf%3A%20529.982.247-25", "CPF 529 982 247 25"])
def test_cpf_robusto_a_ofuscacao(texto):
    assert "BR_CPF" in regras(texto)


@pytest.mark.parametrize("texto", ["protocolo 11111111111", "pedido 12345678901", "nota 52998224726"])
def test_cpf_invalido_nao_dispara(texto):
    assert "BR_CPF" not in regras(texto)


@pytest.mark.parametrize("texto,regra", [
    ("Dona Ana é cadeirante", "SAUDE_CONDICAO"), ("laudo CID F32.1", "SAUDE_CID"), ("CNS 898 0012 3456 7891", "BR_CNS"),
    ("senha=Chuva@2026", "CRED_SENHA"), ('{"password": "abc12345"}', "CRED_SENHA"),
    ("postgres://admin:S3nh4@db:5432/x", "CRED_URL_SENHA"), ("Authorization: Bearer abcdefghijklmnop1234", "CRED_BEARER"),
    ("chave sk-ant-api03-abcdefghijklmnopqrstu", "CRED_API_KEY"), ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJh", "CRED_JWT"),
    ("Zap (11) 98765-4321", "TELEFONE_BR"), ("+55 11 98765-4321", "TELEFONE_BR"), ("maria@gmail.com", "EMAIL"),
    ("Rua Beira-Rio, 45", "ENDERECO"), ("CEP 08061-300", "CEP"), ("-23.49123, -46.43170", "GEOLOC_PRECISA"),
    ("nascimento 12/03/1987", "DATA_NASC"), ("RG 12.345.678-9", "BR_RG"), ("cartão 4111 1111 1111 1111", "CARTAO")])
def test_regras_detectam(texto, regra):
    assert regra in regras(texto)


@pytest.mark.parametrize("texto", ["evento em 12/03/2024", "pedido 08061300", "telefone (00) 12345-6789", "nível 42 cm"])
def test_contexto_evita_falso_positivo(texto):
    assert not M.analisar(texto)


def test_pii_escondida_em_base64():
    b = base64.b64encode(json.dumps({"cpf": CPF}).encode()).decode()
    achados = M.analisar("payload=" + b)
    assert achados and achados[0].codificacao == "base64"
    assert "[BASE64 COM DADO PESSOAL]" in M.mascarar("payload=" + b)


def test_estrutura_usa_nome_do_campo():
    cats = {a.categoria for a in M.analisar_estrutura({"telefone": "11 9 8765 4321", "dados": json.dumps({"cpf": "52998224725"})})}
    assert cats == {"CONTATO", "IDENTIFICACAO"}


def test_mascaramento_idempotente_e_sem_valor_original():
    t = f"CPF {CPF}, senha=abc123, tel (11) 98765-4321, Rua das Garças, 120"
    m1 = M.mascarar(t)
    assert CPF not in m1 and "abc123" not in m1 and "98765-4321" not in m1
    assert M.mascarar(m1) == m1


def test_resultado_nao_guarda_valor_em_claro():
    a = M.analisar(f"cpf {CPF}")[0]
    assert CPF not in json.dumps(a.to_dict()) and len(a.impressao) == 16


def test_regra_nova_por_configuracao(tmp_path):
    cfg = json.loads((RAIZ / "guardiao" / "regras_pii.json").read_text(encoding="utf-8"))
    cfg["regras"].append({"id": "PLACA", "categoria": "IDENTIFICACAO", "padrao": "\\b[A-Z]{3}\\d[A-Z]\\d{2}\\b", "mascara": "id"})
    p = tmp_path / "r.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    from guardiao.pii_engine import MotorPII
    assert {a.regra for a in MotorPII(p).analisar("carro BRA2E19 parado")} == {"PLACA"}


@pytest.fixture(autouse=True)
def _limpo(monkeypatch):
    for var in ("ANTHROPIC_API_KEY", "OLLAMA_MODEL", "OLLAMA_HOST"):
        monkeypatch.delenv(var, raising=False)
    REGISTRO.limpar()
    GUARDIAO.configurar(modo="proteger", fase="teste")
    GUARDIAO.arquivo_auditoria = None
    eventos = []
    GUARDIAO.ouvintes = [eventos.append]
    yield eventos


def test_propagacao_do_rotulo():
    cpf = contaminar(CPF, "IDENTIFICACAO", "teste.cpf", "M-1")
    for derivado in ["CPF: " + cpf, cpf + "!", "%s" % cpf, cpf[:3], cpf.replace(".", ""),
                     cpf.upper(), tjoin(", ", [cpf, "x"])]:
        assert isinstance(derivado, TStr) and derivado.rotulos, derivado
    assert not isinstance(mascarar(cpf), TStr) and CPF not in mascarar(cpf)


def test_bloqueio_em_saida_publica(_limpo):
    saiu = []
    publicar = sink("canal_teste", "publico", acao="bloquear")(saiu.append)
    with pytest.raises(ViolacaoTaint):
        publicar("Cadastro " + contaminar(CPF, "IDENTIFICACAO", "teste.cpf", "M-1"))
    assert saiu == [] and _limpo[-1]["decisao"] == "BLOQUEADO"


def test_lavagem_por_fstring_e_detectada(_limpo):
    saiu = []
    log = sink("log_teste", "log", acao="mascarar")(saiu.append)
    cpf = contaminar(CPF, "IDENTIFICACAO", "teste.cpf", "M-1")
    log(f"usuario {cpf}")
    assert CPF not in saiu[0] and _limpo[-1]["achados"][0]["camada"].startswith("2")


def test_reformatacao_do_cpf_e_detectada(_limpo):
    saiu = []
    log = sink("log_teste", "log", acao="mascarar")(saiu.append)
    contaminar(CPF, "IDENTIFICACAO", "teste.cpf", "M-1")
    log("doc=" + "52998224725")
    assert _limpo[-1]["decisao"] == "MASCARADO"


def test_titular_recebe_o_proprio_endereco_mas_nao_o_de_outro(_limpo):
    saiu = []
    sms = sink("sms_teste", "titular", acao="mascarar", ao_titular={"LOCALIZACAO"})(lambda m, titular=None: saiu.append(m))
    meu = contaminar("Rua das Garças, 120", "LOCALIZACAO", "t.end", "M-1")
    outro = contaminar("Rua Beira-Rio, 45", "LOCALIZACAO", "t.end", "M-2")
    sms("Risco na " + meu, titular="M-1")
    assert "Rua das Garças, 120" in saiu[-1] and _limpo[-1]["decisao"] == "PERMITIDO"
    sms("Risco na " + meu + " e na " + outro, titular="M-1")
    assert "Rua das Garças, 120" in saiu[-1] and "Rua Beira-Rio, 45" not in saiu[-1]


def test_modo_monitorar_registra_vazamento(_limpo):
    GUARDIAO.configurar(modo="monitorar")
    saiu = []
    sink("canal_teste", "publico")(saiu.append)("CPF " + CPF)
    assert saiu == ["CPF " + CPF] and _limpo[-1]["decisao"] == "VAZOU"


def test_auditoria_nao_contem_pii(_limpo):
    sink("log_teste", "log", acao="mascarar")(lambda m: None)(f"cpf {CPF} senha=Xyz@9876")
    assert CPF not in json.dumps(_limpo) and "Xyz@9876" not in json.dumps(_limpo)


VULNERABILIDADES = {
    "VULN-01": ("cadastrar_morador", "log.info"),
    "VULN-02": ("cadastrar_morador", "log.debug"),
    "VULN-03": ("emitir_alerta", "sms.enviar"),
    "VULN-04": ("emitir_alerta", "log.debug"),
    "VULN-05": ("publicar_lista_prioridade", "canal.publicar"),
    "VULN-06": ("exportar_defesa_civil", "defesa_civil.exportar"),
    "VULN-07": ("registrar_ocorrencia", "llm.classificar_ocorrencia"),
    "VULN-08": ("registrar_ocorrencia", "mapa.publicar"),
    "VULN-10": ("consultar_morador", "api.responder"),
}


def test_sast_encontra_todas_as_vulnerabilidades():
    fluxos = analisar_arquivo(RAIZ / "prototipo" / "servico_alerta.py")
    violacoes = {(f.funcao, f.sink.split(" → ")[0]) for f in fluxos if f.status == "VIOLAÇÃO"}
    for vuln, par in VULNERABILIDADES.items():
        assert par in violacoes, f"{vuln} não detectada: {par}"
    assert any(f.status == "SEGREDO NO CÓDIGO" for f in fluxos)
    assert any(f.status == "SANITIZADO" for f in fluxos) and any(f.status == "PERMITIDO" for f in fluxos)


def test_ia_offline_gera_alerta_sem_pii():
    ev = {"sink": "canal_publico_bairro", "tipo": "publico", "decisao": "BLOQUEADO", "local": "x.py:1", "ts": 0,
          "titulares": ["M-1"], "achados": [{"categoria": "SAUDE", "camada": "1-rótulo propagado", "violacao": True}]}
    a = TradutorIA().traduzir(ev)
    assert {"titulo", "mensagem_cidadao", "o_que_fazer", "correcao_tecnica"} <= a.keys()
    assert len(a["mensagem_cidadao"]) <= 280 and not M.analisar(a["mensagem_cidadao"])


def test_saida_do_llm_e_validada_e_mascarada():
    bruto = 'ok {"titulo":"t","mensagem_cidadao":"seu CPF 529.982.247-25 vazou","nivel_risco":"xyz","o_que_fazer":["a"],"o_que_fizemos":"b","correcao_tecnica":"c"}'
    v = _validar(bruto)
    assert CPF not in v["mensagem_cidadao"] and v["nivel_risco"] == "médio"


EV_MASCARADO = {"sink": "exportacao_defesa_civil", "tipo": "exportacao", "decisao": "MASCARADO", "local": "x.py:1",
                "ts": 0, "titulares": ["M-1"], "achados": [{"categoria": "IDENTIFICACAO", "camada": "1", "violacao": True}]}


@pytest.mark.parametrize("mensagem", ["Alerta de enchente! A água está subindo rapidamente.",
                                      "Você foi afetado por um evento que pode comprometer seus dados.",
                                      "Atualize o aplicativo agora para ficar seguro."])
def test_llm_que_inventa_ou_contradiz_e_rejeitado(mensagem):
    from guardiao.ia_remediacao import _offline
    with pytest.raises(ValueError):
        _validar(json.dumps({"titulo": "Alerta", "mensagem_cidadao": mensagem}), _offline(EV_MASCARADO), EV_MASCARADO)


@pytest.mark.parametrize("mensagem", ["Impedimos que seu CPF fosse exposto no SMS.", "Evitamos que seu CPF vazasse.",
                                      "Escondemos seu CPF antes de ele ser exposto.", "Bloqueamos seu CPF para que ele não fosse exposto."])
def test_frase_protetora_nao_e_confundida_com_vazamento(mensagem):
    from guardiao.ia_remediacao import _offline
    assert _validar(json.dumps({"titulo": "t", "mensagem_cidadao": mensagem}), _offline(EV_MASCARADO), EV_MASCARADO)


def test_llm_fiel_aos_fatos_e_aceito_com_nivel_do_codigo():
    from guardiao.ia_remediacao import _offline
    r = {"titulo": "CPF protegido", "mensagem_cidadao": "Tiramos seu CPF do arquivo. Seus dados não foram expostos.",
         "nivel_risco": "crítico"}
    v = _validar(json.dumps(r), _offline(EV_MASCARADO), EV_MASCARADO)
    assert v["nivel_risco"] == "baixo" and v["mensagem_cidadao"].startswith("Tiramos")


@pytest.mark.parametrize("categoria,esperado", [("CREDENCIAL", "Sua senha protegida"), ("NASCIMENTO", "Sua data de nascimento protegida"),
                                                 ("IDENTIFICACAO", "Seu CPF protegido")])
def test_titulo_concorda_em_genero(categoria, esperado):
    from guardiao.ia_remediacao import _offline
    ev = {**EV_MASCARADO, "achados": [{"categoria": categoria, "camada": "1", "violacao": True}]}
    assert _offline(ev)["titulo"].startswith(esperado)


def test_indice_risco_cidadao():
    base = {"tipo": "publico", "exposicao": 1.0, "ts": 0, "titulares": ["M-1"], "sink": "s",
            "achados": [{"categoria": "SAUDE", "camada": "1", "violacao": True}]}
    assert calcular([{**base, "decisao": "VAZOU"}])["indice_atual"] == 100
    assert calcular([{**base, "decisao": "BLOQUEADO"}])["indice_atual"] == 0
    assert calcular([{**base, "decisao": "MASCARADO"}])["nivel"] == "BAIXO"
