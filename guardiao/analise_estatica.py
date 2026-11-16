from __future__ import annotations

import ast
import importlib
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from .pii_engine import motor

ATRIBUTOS = {"cpf": "IDENTIFICACAO", "rg": "IDENTIFICACAO", "telefone": "CONTATO", "email": "CONTATO",
             "endereco": "LOCALIZACAO", "cep": "LOCALIZACAO", "condicao_saude": "SAUDE", "senha": "CREDENCIAL",
             "data_nascimento": "NASCIMENTO"}
TODAS = frozenset(ATRIBUTOS.values())
FONTES_CHAMADA = {"obter_morador", "listar_moradores"}
FONTES_PARAMETRO = {"payload": TODAS, "texto": frozenset({"TEXTO_LIVRE"}), "dados_pessoais": TODAS}
SANITIZADORES = {"mascarar", "pseudonimizar", "mascarar_estrutura"}
NAO_PROPAGA = {"len", "bool", "isinstance", "type", "id", "round", "int", "float"}
OBJ = "OBJ"


@dataclass
class Fluxo:
    id: str
    arquivo: str
    linha: int
    funcao: str
    sink: str
    tipo_sink: str
    categorias: list
    status: str
    fontes: list
    trecho: str


class _Analisador(ast.NodeVisitor):
    def __init__(self, arquivo: Path, sinks_modulo: dict):
        self.arquivo = arquivo
        self.sinks = sinks_modulo
        self.fluxos: list[Fluxo] = []
        self.funcao = "<módulo>"
        self.env: dict[str, frozenset] = {}

    def taint(self, n) -> frozenset:
        if n is None or isinstance(n, ast.Constant):
            return frozenset()
        if isinstance(n, ast.Name):
            return self.env.get(n.id, frozenset())
        if isinstance(n, ast.Attribute):
            base = self.taint(n.value)
            objs = {o for c, o in base if c == OBJ}
            if objs:
                cat = ATRIBUTOS.get(n.attr)
                return frozenset((cat, o + "." + n.attr) for o in objs) if cat else frozenset()
            return base
        if isinstance(n, ast.Subscript):
            base = self.taint(n.value)
            objs = {o for c, o in base if c == OBJ}
            if objs and isinstance(n.slice, ast.Constant) and n.slice.value in ATRIBUTOS:
                return frozenset((ATRIBUTOS[n.slice.value], o) for o in objs)
            return base
        if isinstance(n, ast.Call):
            nome = self._nome_func(n.func)
            curto = nome.split(".")[-1]
            if curto in SANITIZADORES or curto in NAO_PROPAGA:
                return frozenset()
            if curto in FONTES_CHAMADA:
                return frozenset({(OBJ, f"{curto}() L{n.lineno}")})
            t = frozenset().union(*(self.taint(a) for a in n.args), *(self.taint(k.value) for k in n.keywords))
            if isinstance(n.func, ast.Attribute):
                t |= self.taint(n.func.value)
            return t
        if isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            salvo = dict(self.env)
            for g in n.generators:
                self._atribuir(g.target, self.taint(g.iter))
            elt = (self.taint(n.key) | self.taint(n.value)) if isinstance(n, ast.DictComp) else self.taint(n.elt)
            self.env = salvo
            return elt
        if isinstance(n, ast.Dict):
            return frozenset().union(*(self.taint(v) for v in n.values))
        if isinstance(n, ast.Lambda):
            return frozenset()
        return frozenset().union(*(self.taint(c) for c in ast.iter_child_nodes(n)))

    @staticmethod
    def _nome_func(f) -> str:
        if isinstance(f, ast.Name):
            return f.id
        if isinstance(f, ast.Attribute):
            return f"{_Analisador._nome_func(f.value)}.{f.attr}"
        return "?"

    def _atribuir(self, alvo, t):
        if isinstance(alvo, ast.Name):
            self.env[alvo.id] = t
        elif isinstance(alvo, (ast.Tuple, ast.List)):
            for e in alvo.elts:
                self._atribuir(e, t)

    def visit_FunctionDef(self, node):
        ant_env, ant_fn = self.env, self.funcao
        self.env, self.funcao = {}, node.name
        for a in node.args.args:
            if a.arg in FONTES_PARAMETRO:
                self.env[a.arg] = frozenset((c, f"parâmetro '{a.arg}'") for c in FONTES_PARAMETRO[a.arg])
        for st in node.body:
            self._stmt(st)
        self.env, self.funcao = ant_env, ant_fn

    visit_AsyncFunctionDef = visit_FunctionDef

    @staticmethod
    def _chamadas_proprias(st):
        pilha, out = [c for c in ast.iter_child_nodes(st) if not isinstance(c, (ast.stmt, ast.ExceptHandler))], []
        while pilha:
            n = pilha.pop()
            if isinstance(n, ast.Call):
                out.append(n)
            pilha.extend(c for c in ast.iter_child_nodes(n) if not isinstance(c, ast.stmt))
        return sorted(out, key=lambda c: (c.lineno, c.col_offset))

    def _stmt(self, st):
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        for call in self._chamadas_proprias(st):
            self._checar_sink(call)
        if isinstance(st, ast.Assign):
            t = self.taint(st.value)
            for alvo in st.targets:
                self._atribuir(alvo, t)
        elif isinstance(st, ast.AnnAssign) and st.value is not None:
            self._atribuir(st.target, self.taint(st.value))
        elif isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name):
            self.env[st.target.id] = self.env.get(st.target.id, frozenset()) | self.taint(st.value)
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            self._atribuir(st.target, self.taint(st.iter))
        for campo in ("body", "orelse", "finalbody", "handlers"):
            for filho in getattr(st, campo, []) or []:
                if isinstance(filho, ast.ExceptHandler):
                    for s2 in filho.body:
                        self._stmt(s2)
                elif isinstance(filho, ast.stmt):
                    self._stmt(filho)

    def _checar_sink(self, call: ast.Call):
        nome = self._nome_func(call.func)
        pol = self.sinks.get(nome)
        if pol is None:
            return
        args = [*call.args, *(k.value for k in call.keywords if k.arg != "titular")]
        t = frozenset().union(*(self.taint(a) for a in args))
        cats, fontes = set(), set()
        for c, o in t:
            for cc in (TODAS if c == OBJ else {c}):
                cats.add(cc)
            fontes.add(o)
        trecho = ast.unparse(call)
        trecho = trecho if len(trecho) <= 140 else trecho[:137] + "..."
        if not cats:
            if any(isinstance(x, ast.Call) and self._nome_func(x.func).split(".")[-1] in SANITIZADORES
                   for a in args for x in ast.walk(a)):
                self._add(call, nome, pol, [], "SANITIZADO", [], trecho)
            return
        proibidas = {c for c in cats if c not in pol.permitidas and c != "TEXTO_LIVRE"}
        tem_titular = any(k.arg == "titular" for k in call.keywords)
        if "TEXTO_LIVRE" in cats and pol.tipo in ("publico", "terceiro", "log") and "TEXTO_LIVRE" not in pol.permitidas:
            proibidas.add("TEXTO_LIVRE")
        if not proibidas:
            status = "PERMITIDO"
        elif tem_titular and proibidas <= set(pol.ao_titular):
            status = "VERIFICAR EM RUNTIME"
        else:
            status = "VIOLAÇÃO"
        self._add(call, nome, pol, sorted(cats), status, sorted(fontes), trecho)

    def _add(self, call, nome, pol, cats, status, fontes, trecho):
        self.fluxos.append(Fluxo(f"SAST-{len(self.fluxos) + 1:02d}", self.arquivo.name, call.lineno, self.funcao,
                                 f"{nome} → {pol.nome}", pol.tipo, cats, status, fontes, trecho))


def _sinks_do_modulo(arvore: ast.Module) -> dict:
    mapa = {}
    imports = {}
    for n in arvore.body:
        if isinstance(n, ast.ImportFrom) and n.module:
            for a in n.names:
                imports[a.asname or a.name] = n.module
    for n in arvore.body:
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name):
            cls_nome = n.value.func.id
            if cls_nome not in imports:
                continue
            cls = getattr(importlib.import_module(imports[cls_nome]), cls_nome, None)
            for alvo in n.targets:
                if isinstance(alvo, ast.Name) and cls is not None:
                    for metodo in dir(cls):
                        pol = getattr(getattr(cls, metodo), "politica", None)
                        if pol is not None:
                            mapa[f"{alvo.id}.{metodo}"] = pol
    return mapa


def _segredos_no_codigo(arquivo: Path, arvore: ast.Module) -> list[Fluxo]:
    out = []
    for n in ast.walk(arvore):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            for a in motor().analisar(n.value):
                if a.categoria == "CREDENCIAL":
                    out.append(Fluxo("", arquivo.name, n.lineno, "-", "literal no código-fonte", "codigo",
                                     [a.categoria], "SEGREDO NO CÓDIGO", [a.regra], a.valor_mascarado))
    return out


def analisar_arquivo(caminho: str | Path) -> list[Fluxo]:
    caminho = Path(caminho)
    arvore = ast.parse(caminho.read_text(encoding="utf-8"), filename=str(caminho))
    an = _Analisador(caminho, _sinks_do_modulo(arvore))
    for n in arvore.body:
        if isinstance(n, ast.ClassDef):
            for b in n.body:
                if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    an.visit_FunctionDef(b)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            an.visit_FunctionDef(n)
    fluxos = an.fluxos + _segredos_no_codigo(caminho, arvore)
    fluxos.sort(key=lambda f: f.linha)
    for i, f in enumerate(fluxos, 1):
        f.id = f"SAST-{i:02d}"
    return fluxos


def relatorio_markdown(fluxos: list[Fluxo], arquivo: str) -> str:
    from collections import Counter
    c = Counter(f.status for f in fluxos)
    l = [f"# Taint Analysis estático: `{arquivo}`", "",
         "Resumo: " + " · ".join(f"**{k}**: {v}" for k, v in c.most_common()), "",
         "| ID | Linha | Função | Saída (sink) | Categorias | Status | Fonte |", "|---|---|---|---|---|---|---|"]
    for f in fluxos:
        l.append(f"| {f.id} | {f.linha} | `{f.funcao}` | `{f.sink}` | {', '.join(f.categorias) or '-'} | **{f.status}** | {'; '.join(f.fontes)[:70]} |")
    l += ["", "## Trechos", ""]
    for f in fluxos:
        l.append(f"- **{f.id}** (L{f.linha}, {f.status}): `{f.trecho}`")
    return "\n".join(l) + "\n"


if __name__ == "__main__":
    alvo = sys.argv[1] if len(sys.argv) > 1 else "prototipo/servico_alerta.py"
    fl = analisar_arquivo(alvo)
    print(relatorio_markdown(fl, alvo))
    if "--json" in sys.argv:
        print(json.dumps([asdict(f) for f in fl], ensure_ascii=False, indent=1))
