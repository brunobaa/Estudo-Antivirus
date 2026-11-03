"""O scanner: pega cada arquivo e passa por TODOS os motores.

    arquivo ──► motor 1 ──► resultado 1 ┐
            ──► motor 2 ──► resultado 2 ├──► veredito final = o pior deles
            ──► motor N ──► resultado N ┘
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from superav.core.motor import Arquivo, Motor, Resultado, Veredito


@dataclass
class RelatorioArquivo:
    """Tudo o que os motores disseram sobre um arquivo."""

    caminho: Path
    resultados: list[tuple[Motor, Resultado]] = field(default_factory=list)

    @property
    def veredito_final(self) -> Veredito:
        if not self.resultados:
            return Veredito.PENDENTE
        return max(r.veredito for _, r in self.resultados)


def listar_arquivos(alvo: Path) -> Iterator[Path]:
    """Se o alvo é um arquivo, devolve ele; se é pasta, todos os arquivos dentro."""
    alvo = Path(alvo)
    if alvo.is_file():
        yield alvo
    elif alvo.is_dir():
        for caminho in sorted(alvo.rglob("*")):
            if caminho.is_file():
                yield caminho
    else:
        raise FileNotFoundError(f"caminho não encontrado: {alvo}")


def escanear_arquivo(caminho: Path, motores: list[Motor]) -> RelatorioArquivo:
    relatorio = RelatorioArquivo(caminho)

    try:
        arquivo = Arquivo(caminho)
    except OSError as erro:
        for motor in motores:
            relatorio.resultados.append(
                (motor, Resultado(Veredito.ERRO, f"não consegui abrir: {erro}"))
            )
        return relatorio

    for motor in motores:
        if not motor.pronto:
            resultado = Resultado(Veredito.PENDENTE, f"chega na Aula {motor.aula}")
        else:
            try:
                resultado = motor.analisar(arquivo)
            except Exception as erro:  # um motor quebrado não derruba os outros
                resultado = Resultado(Veredito.ERRO, f"{type(erro).__name__}: {erro}")
        relatorio.resultados.append((motor, resultado))

    return relatorio


def escanear(alvo: Path, motores: list[Motor]) -> Iterator[RelatorioArquivo]:
    for caminho in listar_arquivos(alvo):
        yield escanear_arquivo(caminho, motores)
