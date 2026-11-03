"""Linha de comando do Super Antivírus.

    python -m superav escanear <arquivo-ou-pasta> [--motores hash,yara] [--so-ameacas]
    python -m superav motores

Código de saída (igual aos antivírus de verdade, útil em scripts):
    0 = nada encontrado   1 = algo suspeito   2 = ameaça encontrada
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from superav import __version__
from superav.core.motor import Veredito
from superav.core.registro import carregar_motores
from superav.core.relatorio import imprimir_arquivo, imprimir_resumo
from superav.core.scanner import escanear


def _cmd_escanear(args: argparse.Namespace) -> int:
    ids = [i.strip() for i in args.motores.split(",")] if args.motores else None
    motores = carregar_motores(ids)

    relatorios = []
    for relatorio in escanear(Path(args.alvo), motores):
        relatorios.append(relatorio)
        if not args.so_ameacas or relatorio.veredito_final >= Veredito.SUSPEITO:
            imprimir_arquivo(relatorio)
    imprimir_resumo(relatorios)

    pior = max((r.veredito_final for r in relatorios), default=Veredito.LIMPO)
    if pior == Veredito.MALICIOSO:
        return 2
    if pior == Veredito.SUSPEITO:
        return 1
    return 0


def _cmd_motores(_args: argparse.Namespace) -> int:
    print("Motores do Super Antivírus:\n")
    for motor in carregar_motores():
        status = "✅ pronto  " if motor.pronto else "⏳ pendente"
        print(f"  Aula {motor.aula:>2}  {status}  {motor.id:<10} {motor.nome}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Garante que os emojis apareçam certo no terminal do Windows
    for fluxo in (sys.stdout, sys.stderr):
        if hasattr(fluxo, "reconfigure"):
            fluxo.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        prog="superav", description="Super Antivírus: vários motores, um veredito."
    )
    parser.add_argument("--version", action="version", version=f"superav {__version__}")
    sub = parser.add_subparsers(dest="comando", required=True)

    p_scan = sub.add_parser("escanear", help="escaneia um arquivo ou uma pasta")
    p_scan.add_argument("alvo", help="arquivo ou pasta para escanear")
    p_scan.add_argument("--motores", help="só estes motores, separados por vírgula (ex: hash,yara)")
    p_scan.add_argument("--so-ameacas", action="store_true", help="mostra só os arquivos suspeitos/maliciosos")
    p_scan.set_defaults(func=_cmd_escanear)

    p_mot = sub.add_parser("motores", help="lista os motores e o status de cada um")
    p_mot.set_defaults(func=_cmd_motores)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 3
