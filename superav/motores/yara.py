"""Motor: Regras YARA (Aula 5).

YARA é o "idioma" que a indústria usa para descrever malware. Em vez de um
hash exato (Aula 1), uma regra descreve PADRÕES: "tem estes textos, estes
bytes, e o arquivo é deste tamanho".

    superav/regras/*.yar ──compila uma vez──► regras na memória
                                                   │
    arquivo ──────────────────────────────────► match() ──► casou?
                                                        ┌────┴────┐
                                                       SIM       NÃO
                                                        ▼         ▼
                                         severidade da regra   ✅ passou

Precisa da biblioteca `yara-python` (pip install yara-python). Sem ela, o
motor fica pendente em vez de quebrar o programa.
"""

from __future__ import annotations

from pathlib import Path

from superav.core.motor import Arquivo, Motor, Resultado, Veredito
from superav.core.registro import registrar

try:
    import yara
except ImportError:
    yara = None

PASTA_REGRAS = Path(__file__).resolve().parent.parent / "regras"

SEVERIDADES = {"malicioso": Veredito.MALICIOSO, "suspeito": Veredito.SUSPEITO}


def compilar(pasta: Path = PASTA_REGRAS):
    """Compila todos os .yar da pasta. Cada arquivo vira um "namespace".

    O Python lê o TEXTO das regras e entrega pronto ao YARA (sources=...),
    em vez de passar o caminho (filepaths=...). Motivo: a biblioteca em C do
    YARA não abre caminhos com acento no Windows, como "Área de Trabalho".
    """
    fontes = {
        p.stem: p.read_text(encoding="utf-8") for p in sorted(Path(pasta).glob("*.yar"))
    }
    if not fontes:
        return None, 0
    regras = yara.compile(sources=fontes)
    return regras, sum(1 for _ in regras)


def severidade(regra) -> Veredito:
    """Lê o meta "severidade" da regra; se não tiver, é só suspeito."""
    valor = str(regra.meta.get("severidade", "suspeito")).lower()
    return SEVERIDADES.get(valor, Veredito.SUSPEITO)


@registrar
class MotorYara(Motor):
    id = "yara"
    nome = "Regras YARA"
    aula = 5
    pronto = yara is not None

    def __init__(self, pasta: Path = PASTA_REGRAS):
        self.regras = None
        self.total = 0
        self.erro = None
        if yara is None:
            return
        try:
            self.regras, self.total = compilar(pasta)
        except yara.Error as erro:
            # Uma regra com erro de sintaxe não pode derrubar o antivírus inteiro
            self.erro = f"regra com erro: {erro}"

    def analisar(self, arquivo: Arquivo) -> Resultado:
        if self.erro:
            return Resultado(Veredito.ERRO, self.erro)
        if self.regras is None:
            return Resultado.limpo("nenhuma regra carregada")

        casadas = self.regras.match(data=arquivo.dados, timeout=10)
        if not casadas:
            return Resultado.limpo(f"nenhuma das {self.total} regras casou")

        pior = max(severidade(r) for r in casadas)
        nomes = ", ".join(r.rule for r in casadas)
        return Resultado(pior, f"regra(s): {nomes}")
