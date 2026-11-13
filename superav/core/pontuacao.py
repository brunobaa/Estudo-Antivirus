"""Detecção heurística por pontuação, usada pelos motores PE (Aula 4) e de
scripts (Aula 7).

Cada indício estranho vale alguns pontos; a soma vira o veredito:

    0 ───────────── 3 ──────────── 6 ──────────►
    ✅ normal       🟡 suspeito     🚨 vários sinais juntos
"""

from __future__ import annotations

from dataclasses import dataclass, field

from superav.core.motor import Resultado, Veredito

SUSPEITO_A_PARTIR = 3
MALICIOSO_A_PARTIR = 6


@dataclass
class Sinal:
    pontos: int
    texto: str


@dataclass
class Pontuacao:
    sinais: list[Sinal] = field(default_factory=list)
    resumo: dict = field(default_factory=dict)

    def marcar(self, pontos: int, texto: str) -> None:
        self.sinais.append(Sinal(pontos, texto))

    @property
    def pontos(self) -> int:
        return sum(s.pontos for s in self.sinais)


def classificar(pontuacao: Pontuacao, sem_sinais: str = "nenhum indício") -> Resultado:
    pontos = pontuacao.pontos
    detalhes = "; ".join(s.texto for s in pontuacao.sinais)
    if pontos >= MALICIOSO_A_PARTIR:
        return Resultado(Veredito.MALICIOSO, f"{pontos} pts — {detalhes}")
    if pontos >= SUSPEITO_A_PARTIR:
        return Resultado(Veredito.SUSPEITO, f"{pontos} pts — {detalhes}")
    if pontuacao.sinais:
        return Resultado.limpo(f"{pontos} pts — indícios fracos: {detalhes}")
    return Resultado.limpo(sem_sinais)
