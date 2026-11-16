from __future__ import annotations

import random
from dataclasses import dataclass

from guardiao.taint import contaminar

NOMES = ["Ana Lúcia", "José Carlos", "Maria Aparecida", "Francisco", "Antônia", "João Pedro", "Rita de Cássia",
         "Severino", "Josefa", "Raimundo", "Luzia", "Edson", "Cícera", "Valdir", "Marlene", "Gilmar", "Neide",
         "Adriano", "Sebastiana", "Reginaldo", "Débora", "Wellington", "Irene", "Cláudio"]
SOBRENOMES = ["Silva", "Santos", "Oliveira", "Souza", "Lima", "Pereira", "Ferreira", "Alves", "Nascimento", "Costa"]
RUAS = ["Rua das Garças", "Rua Beira-Rio", "Travessa do Brejo", "Rua dos Açudes", "Rua da Várzea",
        "Viela das Taboas", "Rua Lagoa Azul", "Rua do Aterro"]
CONDICOES = ["cadeirante", "acamado", "gestante", "insulino-dependente", "oxigênio domiciliar", "deficiência visual"]


def gerar_cpf(rnd: random.Random) -> str:
    d = [rnd.randint(0, 9) for _ in range(9)]
    for n in (9, 10):
        s = sum(d[i] * (n + 1 - i) for i in range(n))
        d.append((s * 10 % 11) % 10)
    s = "".join(map(str, d))
    return f"{s[:3]}.{s[3:6]}.{s[6:9]}-{s[9:]}"


@dataclass
class Morador:
    id: str
    nome: str
    cpf: str
    telefone: str
    email: str
    endereco: str
    cep: str
    condicao_saude: str | None
    senha: str
    area_risco: str


def _bruto(n=24, seed=2026) -> list[dict]:
    rnd = random.Random(seed)
    out = []
    for i in range(n):
        nome = f"{NOMES[i % len(NOMES)]} {rnd.choice(SOBRENOMES)}"
        out.append({
            "id": f"M-{i + 1:04d}", "nome": nome, "cpf": gerar_cpf(rnd),
            "telefone": f"(11) 9{rnd.randint(1000, 9999)}-{rnd.randint(1000, 9999)}",
            "email": f"{nome.split()[0].lower().replace('í', 'i').replace('á', 'a').replace('ô', 'o').replace('é', 'e')}{rnd.randint(10, 99)}@exemplo.com.br",
            "endereco": f"{rnd.choice(RUAS)}, {rnd.randint(10, 990)}",
            "cep": f"080{rnd.randint(10, 99)}-{rnd.randint(100, 999)}",
            "condicao_saude": rnd.choice(CONDICOES) if rnd.random() < 0.35 else None,
            "senha": f"Chuva@{rnd.randint(1000, 9999)}",
            "area_risco": "ALTA" if rnd.random() < 0.6 else "MEDIA"})
    return out


class RepositorioMoradores:

    def __init__(self, n=24, seed=2026):
        self._dados = {d["id"]: d for d in _bruto(n, seed)}

    def _hidratar(self, d: dict) -> Morador:
        t = d["id"]
        orig = f"banco.moradores[{t}]"
        return Morador(
            id=t, nome=d["nome"],
            cpf=contaminar(d["cpf"], "IDENTIFICACAO", orig + ".cpf", t),
            telefone=contaminar(d["telefone"], "CONTATO", orig + ".telefone", t),
            email=contaminar(d["email"], "CONTATO", orig + ".email", t),
            endereco=contaminar(d["endereco"], "LOCALIZACAO", orig + ".endereco", t),
            cep=contaminar(d["cep"], "LOCALIZACAO", orig + ".cep", t),
            condicao_saude=contaminar(d["condicao_saude"], "SAUDE", orig + ".condicao_saude", t),
            senha=contaminar(d["senha"], "CREDENCIAL", orig + ".senha", t),
            area_risco=d["area_risco"])

    def obter_morador(self, mid: str) -> Morador:
        return self._hidratar(self._dados[mid])

    def listar_moradores(self, area: str | None = None) -> list[Morador]:
        return [self._hidratar(d) for d in self._dados.values() if area is None or d["area_risco"] == area]

    def total(self) -> int:
        return len(self._dados)
