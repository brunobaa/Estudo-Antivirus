"""Motor: Assinatura (hash) (Aula 1).

Calcula o hash do arquivo e procura na base de assinaturas de malware
conhecido (superav/assinaturas/*.txt).

    arquivo ──► SHA-256 ──► está na base? ──SIM──► 🚨 não passou (nome da ameaça)
                                          └─NÃO──► ✅ passou
"""

from __future__ import annotations

from pathlib import Path

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.registro import registrar

PASTA_ASSINATURAS = Path(__file__).resolve().parent.parent / "assinaturas"

# O tamanho do hash em hexadecimal denuncia o algoritmo
ALGORITMO_POR_TAMANHO = {32: "md5", 40: "sha1", 64: "sha256"}
HEXADECIMAL = set("0123456789abcdef")

# Base = {algoritmo: {hash: nome da ameaça}}
Base = dict[str, dict[str, str]]


def interpretar_linha(linha: str) -> tuple[str, str, str] | None:
    """Transforma uma linha da base em (algoritmo, hash, nome), ou None se inválida."""
    linha = linha.split("#", 1)[0].strip()  # tira comentários
    if not linha:
        return None
    partes = linha.split(maxsplit=1)
    valor = partes[0].lower()
    algoritmo = ALGORITMO_POR_TAMANHO.get(len(valor))
    if algoritmo is None or not set(valor) <= HEXADECIMAL:
        return None
    nome = partes[1].strip() if len(partes) > 1 else "Malware.SemNome"
    return algoritmo, valor, nome


def carregar_base(pasta: Path = PASTA_ASSINATURAS) -> Base:
    """Lê todos os .txt da pasta de assinaturas."""
    base: Base = {}
    for arquivo in sorted(Path(pasta).glob("*.txt")):
        for linha in arquivo.read_text(encoding="utf-8").splitlines():
            entrada = interpretar_linha(linha)
            if entrada:
                algoritmo, valor, nome = entrada
                base.setdefault(algoritmo, {})[valor] = nome
    return base


@registrar
class MotorHash(Motor):
    id = "hash"
    nome = "Assinatura (hash)"
    aula = 1
    pronto = True

    def __init__(self, pasta: Path = PASTA_ASSINATURAS):
        # A base é carregada UMA vez, e não a cada arquivo
        self.base = carregar_base(pasta)
        self.total = sum(len(assinaturas) for assinaturas in self.base.values())

    def analisar(self, arquivo: Arquivo) -> Resultado:
        # Só calcula os algoritmos que existem na base (sha256 quase sempre)
        for algoritmo, assinaturas in self.base.items():
            valor = arquivo.hash(algoritmo)
            if valor in assinaturas:  # busca num dict: O(1), instantânea
                return Resultado.malicioso(f"{assinaturas[valor]} ({algoritmo})")
        return Resultado.limpo(f"fora das {self.total} assinaturas")
