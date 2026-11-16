from __future__ import annotations

import base64
import json

from guardiao.taint import ViolacaoTaint, contaminar_registro, mascarar, pseudonimizar, tjoin
from prototipo.moradores import RepositorioMoradores
from prototipo.saidas import APIPublica, CanalPublicoBairro, DefesaCivil, GatewaySMS, IAExterna, Log, MapaOcorrencias

log = Log()
sms = GatewaySMS()
canal = CanalPublicoBairro()
mapa = MapaOcorrencias()
defesa_civil = DefesaCivil()
api = APIPublica()
llm = IAExterna()


class ServicoAlerta:
    def __init__(self, repo: RepositorioMoradores | None = None):
        self.repo = repo or RepositorioMoradores()
        self.bloqueios = 0

    def cadastrar_morador(self, payload: dict) -> str:
        dados = contaminar_registro(payload, "api:POST /moradores")
        log.info(f"Novo cadastro recebido: {dados}")
        bruto = base64.b64encode(json.dumps(payload).encode()).decode()
        log.debug("payload bruto do app (b64): " + bruto)
        return "M-NOVO"

    def emitir_alerta(self, nivel: str, chuva_prevista_mm: float) -> int:
        enviados = 0
        for m in self.repo.listar_moradores(area="ALTA"):
            msg = ("AlertaChuva: " + m.nome + ", risco " + nivel + " de alagamento amanhã (" +
                   str(round(chuva_prevista_mm)) + " mm) na " + m.endereco +
                   ". Seu cadastro: CPF " + m.cpf + ". Suba documentos e remédios.")
            sms.enviar(m.telefone, msg, titular=m.id)
            log.debug("SMS enviado para %s" % m.telefone)
            log.info("Alerta entregue ao morador " + mascarar(m.telefone))
            enviados += 1
        canal.publicar(f"⚠ Risco {nivel} de alagamento amanhã no Jardim Pantanal. "
                       f"{enviados} moradores avisados por SMS. Defesa Civil: 199.")
        return enviados

    def publicar_lista_prioridade(self) -> None:
        prioritarios = [m for m in self.repo.listar_moradores() if m.condicao_saude]
        linhas = [m.nome + " (" + m.condicao_saude + ") - " + m.endereco + " - " + m.telefone for m in prioritarios]
        try:
            canal.publicar("Prioridade de resgate: " + tjoin("; ", linhas))
        except ViolacaoTaint:
            self.bloqueios += 1
            canal.publicar(f"{len(prioritarios)} famílias com prioridade de resgate foram informadas à Defesa Civil.")

    def exportar_defesa_civil(self) -> None:
        linhas = [{"cpf": m.cpf, "endereco": m.endereco, "telefone": m.telefone,
                   "condicao_saude": m.condicao_saude} for m in self.repo.listar_moradores() if m.condicao_saude]
        defesa_civil.exportar(linhas)
        ids = [{"ref": pseudonimizar(m.cpf), "endereco": m.endereco, "condicao_saude": m.condicao_saude}
               for m in self.repo.listar_moradores() if m.condicao_saude]
        defesa_civil.exportar(ids)

    def registrar_ocorrencia(self, autor_id: str, texto: str, lat: float, lon: float) -> str:
        categoria = llm.classificar_ocorrencia(f"Classifique a ocorrência: {texto}")
        mapa.publicar({"categoria": categoria, "relato": texto,
                       "local": f"{lat:.5f}, {lon:.5f}"})
        return categoria

    def ingerir_leitura_sensor(self, leitura: dict) -> None:
        try:
            if leitura.get("nivel_cm") is None:
                raise ConnectionError("broker mqtt://sensor:Pnt4n4l#2026@mqtt.alertachuva.local:1883 recusou "
                                      "a conexão (token Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJlc3AzMiJ9.c2lnbmF0dXJh)")
            log.info(f"sensor {leitura['sensor']}: nível {leitura['nivel_cm']} cm")
        except ConnectionError as e:
            log.error(f"falha na ingestão: {e}")

    def consultar_morador(self, mid: str, solicitante: str | None) -> dict | None:
        m = self.repo.obter_morador(mid)
        try:
            corpo = {k: v for k, v in vars(m).items() if k != "senha"}
            return api.responder(corpo, titular=solicitante)
        except ViolacaoTaint:
            self.bloqueios += 1
            return None
