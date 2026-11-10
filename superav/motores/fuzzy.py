"""Motor: Hash por semelhança (fuzzy hashing) (Aula 6).

O SHA-256 (Aula 1) muda por inteiro se 1 byte mudar. O ssdeep faz o contrário:
arquivos PARECIDOS geram hashes PARECIDOS, e dá para medir quanto (0 a 100).

    familia-v1.txt ──► 96:Dg2G+qseZ6j57ngiQB9dqtA42QCZ0GNPE1yE/V...
                             ▲▲▲▲  ▲▲▲▲▲▲▲▲▲▲▲  ▲▲▲  ▲▲▲▲▲▲▲▲▲▲▲   muitos pedaços iguais
    familia-v2.txt ──► 96:D52G+KeZ6j57ngiQVNql3CZ0GNPE1LE/V...
                                                       semelhança: 85 / 100

Precisa da biblioteca `ppdeep` (pip install ppdeep). Sem ela, o motor fica
pendente em vez de quebrar o programa.
"""

from __future__ import annotations

from pathlib import Path

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.registro import registrar

try:
    import ppdeep
except ImportError:
    ppdeep = None

# Todos os arquivos .ssdeep desta pasta (fuzzy.ssdeep, minhas.ssdeep, ...)
BASE_FUZZY = Path(__file__).resolve().parent.parent / "assinaturas"

TAMANHO_MINIMO = 4096              # abaixo disso o ssdeep não tem pedaços suficientes
TAMANHO_MAXIMO = 10 * 1024 * 1024  # o ppdeep é Python puro: arquivos enormes ficam lentos
MALICIOSO_A_PARTIR = 80            # quase igual a uma família conhecida
SUSPEITO_A_PARTIR = 50             # parentesco forte


def carregar_base(caminho: Path = BASE_FUZZY) -> list[tuple[str, str]]:
    """Lê a base: lista de (hash ssdeep, nome da família).

    `caminho` pode ser uma pasta (lê todos os .ssdeep) ou um arquivo só.
    """
    caminho = Path(caminho)
    if caminho.is_dir():
        arquivos = sorted(caminho.glob("*.ssdeep"))
    else:
        arquivos = [caminho] if caminho.exists() else []
    linhas = [l for a in arquivos for l in a.read_text(encoding="utf-8").splitlines()]

    base = []
    for linha in linhas:
        linha = linha.split("#", 1)[0].strip()
        if not linha:
            continue
        partes = linha.split(maxsplit=1)
        if partes[0].count(":") != 2:  # formato bloco:hash1:hash2
            continue
        nome = partes[1].strip() if len(partes) > 1 else "Familia.SemNome"
        base.append((partes[0], nome))
    return base


def mais_parecido(valor: str, base: list[tuple[str, str]]) -> tuple[int, str]:
    """Compara com todas as assinaturas e devolve (melhor nota, nome)."""
    melhor, nome_melhor = 0, ""
    for assinatura, nome in base:
        nota = ppdeep.compare(valor, assinatura)
        if nota > melhor:
            melhor, nome_melhor = nota, nome
    return melhor, nome_melhor


@registrar
class MotorFuzzy(Motor):
    id = "fuzzy"
    nome = "Hash por semelhança"
    aula = 6
    pronto = ppdeep is not None

    def __init__(self, base: Path = BASE_FUZZY):
        self.base = carregar_base(base)

    def analisar(self, arquivo: Arquivo) -> Resultado:
        if arquivo.tamanho < TAMANHO_MINIMO:
            return Resultado.limpo(f"pequeno demais para comparar ({arquivo.tamanho} bytes)")
        if arquivo.tamanho > TAMANHO_MAXIMO:
            return Resultado.limpo("grande demais para o fuzzy (limite 10 MB)")
        if not self.base:
            return Resultado.limpo("nenhuma assinatura fuzzy na base")

        nota, familia = mais_parecido(ppdeep.hash(arquivo.dados), self.base)
        if nota >= MALICIOSO_A_PARTIR:
            return Resultado.malicioso(f"{nota}% parecido com {familia}")
        if nota >= SUSPEITO_A_PARTIR:
            return Resultado.suspeito(f"{nota}% parecido com {familia}")
        n = len(self.base)
        return Resultado.limpo(f"no máximo {nota}% parecido com a base ({n} família{'s' if n != 1 else ''})")
