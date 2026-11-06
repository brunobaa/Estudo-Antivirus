"""Motor: Entropia (Aula 3).

Entropia de Shannon mede o quão "imprevisível" é cada byte, de 0 a 8 bits/byte:

    0 ─────────── 4 ──────── 6 ──────── 7.2 ──── 8
    "AAAAAAA"    texto     programa   compactado/criptografado
    (tudo igual) comum     normal     (parece ruído aleatório)

Conteúdo criptografado ou compactado tem entropia perto de 8. Isso é normal num
.zip ou .jpg, mas é estranho num .exe (packer escondendo o código) ou num .txt
(arquivo sequestrado por ransomware).
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.registro import registrar
from superav.motores.tipo import identificar

TAMANHO_BLOCO = 4096          # a entropia é medida em pedaços de 4 KB
LIMITE_ANALISE = 32 * 1024 * 1024  # analisa no máximo os primeiros 32 MB
TAMANHO_MINIMO = 512          # abaixo disso a medida não é confiável
ALTA = 7.2                    # a partir daqui, "parece aleatório"

# Formatos que JÁ SÃO compactados: entropia alta é o esperado
CATEGORIAS_COMPACTADAS = {"compactado", "imagem", "midia"}


def entropia(dados: bytes) -> float:
    """Entropia de Shannon em bits por byte (0.0 a 8.0).

        H = - Σ p(x) · log2 p(x)    para cada valor de byte x que aparece
    """
    return _entropia_de_contagem(Counter(dados), len(dados))


def _entropia_de_contagem(contagem: Counter, total: int) -> float:
    """Mesma fórmula, a partir de uma contagem de bytes já feita."""
    if not total:
        return 0.0
    return -sum((n / total) * math.log2(n / total) for n in contagem.values())


@dataclass
class Medida:
    geral: float              # entropia do arquivo inteiro
    blocos: list[float]       # entropia de cada bloco de 4 KB
    analisados: int           # quantos bytes foram analisados

    @property
    def fracao_alta(self) -> float:
        """Que parte dos blocos parece aleatória (0.0 a 1.0)."""
        if not self.blocos:
            return 0.0
        return sum(b >= ALTA for b in self.blocos) / len(self.blocos)


def medir(dados: bytes, tamanho_bloco: int = TAMANHO_BLOCO) -> Medida:
    """Mede a entropia geral e a de cada bloco, lendo os dados uma vez só."""
    dados = dados[:LIMITE_ANALISE]
    total = Counter()
    blocos = []
    for inicio in range(0, len(dados), tamanho_bloco):
        bloco = dados[inicio:inicio + tamanho_bloco]
        contagem = Counter(bloco)
        total.update(contagem)  # a contagem geral é a soma das contagens dos blocos
        blocos.append(_entropia_de_contagem(contagem, len(bloco)))
    return Medida(_entropia_de_contagem(total, len(dados)), blocos, len(dados))


@registrar
class MotorEntropia(Motor):
    id = "entropia"
    nome = "Entropia"
    aula = 3
    pronto = True

    def analisar(self, arquivo: Arquivo) -> Resultado:
        if arquivo.tamanho < TAMANHO_MINIMO:
            return Resultado.limpo(f"pequeno demais para medir ({arquivo.tamanho} bytes)")

        medida = medir(arquivo.dados)
        valor = f"{medida.geral:.2f} bits/byte"
        real = identificar(arquivo.cabecalho(64))

        # 1. Já é um formato compactado: alta entropia é normal
        if real and real.categoria in CATEGORIAS_COMPACTADAS:
            return Resultado.limpo(f"{valor}, normal para {real.nome}")

        # 2. Executável quase todo "aleatório": sinal clássico de packer
        if real and real.categoria == "executavel":
            if medida.fracao_alta >= 0.5:
                return Resultado.suspeito(
                    f"{valor}; {medida.fracao_alta:.0%} do executável parece "
                    f"compactado/cifrado (packer?)"
                )
            return Resultado.limpo(f"{valor}, normal para executável")

        # 3. Texto, documento ou formato desconhecido com cara de ruído
        if medida.geral >= ALTA:
            return Resultado.suspeito(
                f"{valor}: parece criptografado, mas não é um formato compactado conhecido"
            )
        return Resultado.limpo(valor)
