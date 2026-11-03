"""Mostra os resultados no terminal, no formato:

    📄 amostras/foto.jpg.exe
       Assinatura (hash)       ✅ passou
       Regras YARA             🚨 não passou   regra Trojan_X
       Entropia                🟡 suspeito     7.91 bits/byte
       ─────────────────────────
       Veredito final: 🚨 MALICIOSO
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from superav.core.motor import Veredito
from superav.core.scanner import RelatorioArquivo

ROTULOS = {
    Veredito.PENDENTE: "⏳ pendente",
    Veredito.ERRO: "❌ erro",
    Veredito.LIMPO: "✅ passou",
    Veredito.SUSPEITO: "🟡 suspeito",
    Veredito.MALICIOSO: "🚨 não passou",
}

FINAL = {
    Veredito.PENDENTE: "⏳ SEM MOTORES PRONTOS",
    Veredito.ERRO: "❌ NÃO FOI POSSÍVEL ANALISAR",
    Veredito.LIMPO: "✅ LIMPO",
    Veredito.SUSPEITO: "🟡 SUSPEITO",
    Veredito.MALICIOSO: "🚨 MALICIOSO",
}


def _caminho_bonito(caminho: Path) -> str:
    try:
        return str(caminho.resolve().relative_to(Path.cwd()))
    except ValueError:
        return str(caminho)


def imprimir_arquivo(relatorio: RelatorioArquivo) -> None:
    largura = max((len(m.nome) for m, _ in relatorio.resultados), default=10) + 2
    print(f"\n📄 {_caminho_bonito(relatorio.caminho)}")
    for motor, resultado in relatorio.resultados:
        rotulo = ROTULOS[resultado.veredito]
        print(f"   {motor.nome:<{largura}} {rotulo:<14} {resultado.detalhe}".rstrip())
    print("   " + "─" * (largura + 15))
    print(f"   Veredito final: {FINAL[relatorio.veredito_final]}")


def imprimir_resumo(relatorios: list[RelatorioArquivo]) -> None:
    contagem = Counter(r.veredito_final for r in relatorios)
    print("\n══════════════════ Resumo ══════════════════")
    print(f"  Arquivos analisados: {len(relatorios)}")
    print(
        f"  ✅ Limpos: {contagem[Veredito.LIMPO]}   "
        f"🟡 Suspeitos: {contagem[Veredito.SUSPEITO]}   "
        f"🚨 Maliciosos: {contagem[Veredito.MALICIOSO]}"
    )
    outros = contagem[Veredito.PENDENTE] + contagem[Veredito.ERRO]
    if outros:
        print(f"  ⏳/❌ Sem veredito: {outros}")
    print("════════════════════════════════════════════")
