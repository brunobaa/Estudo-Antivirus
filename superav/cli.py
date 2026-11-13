"""Linha de comando do Super Antivírus.

    python -m superav escanear <arquivo-ou-pasta> [--motores hash,yara] [--so-ameacas]
    python -m superav motores
    python -m superav hash <arquivo>
    python -m superav cabecalho <arquivo> [--bytes 64]
    python -m superav entropia <arquivo> [--linhas 16]
    python -m superav pe <arquivo>
    python -m superav yara <arquivo>
    python -m superav fuzzy <arquivo> [<outro-arquivo>]
    python -m superav script <arquivo>
    python -m superav adicionar-assinatura <arquivo> --nome Nome.Da.Ameaca

Código de saída (igual aos antivírus de verdade, útil em scripts):
    0 = nada encontrado   1 = algo suspeito   2 = ameaça encontrada
"""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

from superav import __version__
from superav.core.motor import Arquivo, Veredito
from superav.core.registro import carregar_motores
from superav.core.relatorio import imprimir_arquivo, imprimir_resumo
from superav.core.scanner import escanear
from superav.motores.hash import PASTA_ASSINATURAS, carregar_base
from superav.motores.entropia import ALTA, TAMANHO_BLOCO, medir
from superav.motores.tipo import extensoes, identificar


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


def _abrir_arquivo(caminho: str) -> Arquivo:
    if not Path(caminho).is_file():
        raise FileNotFoundError(f"não é um arquivo: {caminho}")
    return Arquivo(Path(caminho))


def _cmd_hash(args: argparse.Namespace) -> int:
    arquivo = _abrir_arquivo(args.arquivo)
    print(f"📄 {arquivo.caminho}  ({arquivo.tamanho} bytes)")
    for algoritmo in ("md5", "sha1", "sha256"):
        print(f"   {algoritmo:<7} {arquivo.hash(algoritmo)}")
    return 0


def _cmd_cabecalho(args: argparse.Namespace) -> int:
    """Mostra os primeiros bytes em hexadecimal, como um editor hex."""
    arquivo = _abrir_arquivo(args.arquivo)
    dados = arquivo.cabecalho(args.bytes)
    real = identificar(arquivo.cabecalho(64))
    ext, _ = extensoes(arquivo.caminho.name)

    print(f"📄 {arquivo.caminho}  ({arquivo.tamanho} bytes)\n")
    print("  posição  " + " ".join(f"{i:02X}" for i in range(16)) + "   texto")
    for inicio in range(0, len(dados), 16):
        linha = dados[inicio:inicio + 16]
        hexa = " ".join(f"{b:02X}" for b in linha).ljust(47)
        texto = "".join(chr(b) if 32 <= b < 127 else "." for b in linha)
        print(f"  {inicio:08X} {hexa}   {texto}")

    print(f"\n  extensão no nome: .{ext}" if ext else "\n  extensão no nome: (nenhuma)")
    if real:
        magic = " ".join(f"{b:02X}" for b in real.magic)
        onde = f" na posição {real.deslocamento}" if real.deslocamento else ""
        print(f"  tipo real:        {real.nome}  (magic bytes {magic}{onde})")
    else:
        print("  tipo real:        desconhecido (sem magic bytes da nossa tabela)")
    return 0


def _barra(valor: float, largura: int = 32) -> str:
    cheio = round(valor / 8 * largura)
    return "█" * cheio + "░" * (largura - cheio)


def _cmd_entropia(args: argparse.Namespace) -> int:
    """Desenha a entropia ao longo do arquivo, pedaço por pedaço."""
    arquivo = _abrir_arquivo(args.arquivo)
    medida = medir(arquivo.dados)
    print(f"📄 {arquivo.caminho}  ({arquivo.tamanho} bytes)\n")
    print(f"  entropia geral: {_barra(medida.geral)} {medida.geral:.2f} / 8 bits/byte\n")

    if not medida.blocos:
        return 0
    # Junta os blocos em no máximo `--linhas` faixas, para caber na tela
    por_linha = max(1, math.ceil(len(medida.blocos) / args.linhas))
    print("  posição        entropia por trecho          (0 ─── 4 ─── 7.2 ─ 8)")
    for i in range(0, len(medida.blocos), por_linha):
        grupo = medida.blocos[i:i + por_linha]
        valor = sum(grupo) / len(grupo)
        alerta = "  ◄ parece aleatório" if valor >= ALTA else ""
        print(f"  {i * TAMANHO_BLOCO:>10,}  {_barra(valor)} {valor:4.2f}{alerta}")
    print(f"\n  cada linha = {por_linha * TAMANHO_BLOCO // 1024} KB;"
          f" {medida.fracao_alta:.0%} dos trechos acima de {ALTA}")
    return 0


def _cmd_pe(args: argparse.Namespace) -> int:
    """Raio-X de um executável do Windows: seções, imports e veredito."""
    import superav.motores.pe as mpe
    from superav.core.relatorio import ROTULOS

    if mpe.pefile is None:
        print("erro: a biblioteca pefile não está instalada (pip install pefile)", file=sys.stderr)
        return 3

    arquivo = _abrir_arquivo(args.arquivo)
    print(f"📄 {arquivo.caminho}  ({arquivo.tamanho:,} bytes)\n")

    pe = mpe.pefile.PE(data=arquivo.dados, fast_load=True)
    pe.parse_data_directories(
        directories=[mpe.pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    print("  seção        tam.(bytes)  entropia  flags (X=exec W=grava R=lê)")
    for s in pe.sections:
        nome = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        f = s.Characteristics
        marcas = ("X" if f & 0x20000000 else "-") + ("W" if f & 0x80000000 else "-") + ("R" if f & 0x40000000 else "-")
        print(f"  {nome:<12} {s.SizeOfRawData:>10,}  {s.get_entropy():>7.2f}  {marcas}")

    dlls = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    total = sum(len(d.imports) for d in dlls)
    print(f"\n  imports: {total} funções de {len(dlls)} DLLs")
    pe.close()

    resultado = mpe.MotorPE().analisar(arquivo)
    print(f"\n  Veredito: {ROTULOS[resultado.veredito]}  {resultado.detalhe}")
    return 0


def _cmd_yara(args: argparse.Namespace) -> int:
    """Mostra quais regras YARA casaram e ONDE no arquivo cada trecho apareceu."""
    import superav.motores.yara as myara
    from superav.core.relatorio import ROTULOS

    if myara.yara is None:
        print("erro: a biblioteca yara-python não está instalada (pip install yara-python)", file=sys.stderr)
        return 3

    arquivo = _abrir_arquivo(args.arquivo)
    regras, total = myara.compilar()
    print(f"📄 {arquivo.caminho}  ({arquivo.tamanho:,} bytes)   {total} regras carregadas\n")

    casadas = regras.match(data=arquivo.dados, timeout=10) if regras else []
    if not casadas:
        print("  nenhuma regra casou ✅")
        return 0

    for regra in casadas:
        veredito = myara.severidade(regra)
        print(f"  {ROTULOS[veredito]}  {regra.rule}")
        if "descricao" in regra.meta:
            print(f"      {regra.meta['descricao']}")
        for achado in regra.strings:
            for ocorrencia in achado.instances[:3]:
                trecho = ocorrencia.matched_data[:40].decode("latin-1").replace("\n", " ")
                print(f"      {achado.identifier:<8} posição {ocorrencia.offset:>6}  \"{trecho}\"")
        if not regra.strings:
            print("      (casou só pela condition, sem strings)")
        print()
    return 0


def _cmd_fuzzy(args: argparse.Namespace) -> int:
    """Mostra o hash ssdeep; com 2 arquivos, mede a semelhança entre eles."""
    import superav.motores.fuzzy as mfuzzy

    if mfuzzy.ppdeep is None:
        print("erro: a biblioteca ppdeep não está instalada (pip install ppdeep)", file=sys.stderr)
        return 3

    hashes = []
    for caminho in args.arquivos:
        arquivo = _abrir_arquivo(caminho)
        valor = mfuzzy.ppdeep.hash(arquivo.dados)
        hashes.append(valor)
        print(f"📄 {arquivo.caminho}  ({arquivo.tamanho:,} bytes)")
        print(f"   ssdeep  {valor}")
        print(f"   sha256  {arquivo.hash()}\n")

    if len(hashes) == 2:
        nota = mfuzzy.ppdeep.compare(*hashes)
        print(f"  semelhança: {_barra(nota / 100 * 8)} {nota}%")
    else:
        nota, familia = mfuzzy.mais_parecido(hashes[0], mfuzzy.carregar_base())
        alvo = f" ({familia})" if familia else ""
        print(f"  mais parecido na base: {_barra(nota / 100 * 8)} {nota}%{alvo}")
    return 0


def _cmd_script(args: argparse.Namespace) -> int:
    """Lista cada indício encontrado num script, com os pontos de cada um."""
    from superav.core.pontuacao import MALICIOSO_A_PARTIR, SUSPEITO_A_PARTIR
    from superav.core.relatorio import ROTULOS
    from superav.motores.scripts import MotorScripts, analisar_texto, decodificar, e_script

    arquivo = _abrir_arquivo(args.arquivo)
    print(f"📄 {arquivo.caminho}  ({arquivo.tamanho:,} bytes)\n")
    if not e_script(arquivo.caminho.name):
        print("  (a extensão não é de script, mas vou analisar o texto mesmo assim)\n")

    pontuacao = analisar_texto(decodificar(arquivo.dados))
    if not pontuacao.sinais:
        print("  nenhum indício encontrado")
    for sinal in pontuacao.sinais:
        print(f"  +{sinal.pontos}  {sinal.texto}")

    total = pontuacao.pontos
    print(f"\n  total: {total} pts   (🟡 a partir de {SUSPEITO_A_PARTIR}, 🚨 a partir de {MALICIOSO_A_PARTIR})")
    resultado = MotorScripts().analisar(arquivo)
    print(f"  Veredito do motor: {ROTULOS[resultado.veredito]}")
    return 0


def _cmd_adicionar_assinatura(args: argparse.Namespace) -> int:
    arquivo = _abrir_arquivo(args.arquivo)
    if args.fuzzy:
        return _adicionar_fuzzy(arquivo, args.nome)
    valor = arquivo.hash("sha256")
    destino = PASTA_ASSINATURAS / "minhas.txt"
    if valor in carregar_base().get("sha256", {}):
        print(f"já está na base: {valor}")
        return 0
    novo = not destino.exists()
    with open(destino, "a", encoding="utf-8") as f:
        if novo:
            f.write("# Assinaturas adicionadas com: python -m superav adicionar-assinatura\n")
        f.write(f"{valor}  {args.nome}\n")
    print(f"✅ assinatura adicionada em {destino.name}: {valor}  {args.nome}")
    return 0


def _adicionar_fuzzy(arquivo: Arquivo, nome: str) -> int:
    import superav.motores.fuzzy as mfuzzy

    if mfuzzy.ppdeep is None:
        print("erro: a biblioteca ppdeep não está instalada (pip install ppdeep)", file=sys.stderr)
        return 3
    if arquivo.tamanho < mfuzzy.TAMANHO_MINIMO:
        print(f"erro: arquivo pequeno demais para fuzzy (mínimo {mfuzzy.TAMANHO_MINIMO} bytes)",
              file=sys.stderr)
        return 3
    valor = mfuzzy.ppdeep.hash(arquivo.dados)
    destino = PASTA_ASSINATURAS / "minhas.ssdeep"
    novo = not destino.exists()
    with open(destino, "a", encoding="utf-8") as f:
        if novo:
            f.write("# Assinaturas fuzzy adicionadas com: adicionar-assinatura --fuzzy\n")
        f.write(f"{valor}  {nome}\n")
    print(f"✅ assinatura fuzzy adicionada em {destino.name}: {valor}  {nome}")
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

    p_hash = sub.add_parser("hash", help="mostra o MD5, SHA-1 e SHA-256 de um arquivo")
    p_hash.add_argument("arquivo")
    p_hash.set_defaults(func=_cmd_hash)

    p_cab = sub.add_parser("cabecalho", help="mostra os primeiros bytes (hex) e o tipo real")
    p_cab.add_argument("arquivo")
    p_cab.add_argument("--bytes", type=int, default=32, help="quantos bytes mostrar (padrão 32)")
    p_cab.set_defaults(func=_cmd_cabecalho)

    p_pe = sub.add_parser("pe", help="raio-X de um executável do Windows (seções e imports)")
    p_pe.add_argument("arquivo")
    p_pe.set_defaults(func=_cmd_pe)

    p_yara = sub.add_parser("yara", help="mostra quais regras YARA casaram e onde")
    p_yara.add_argument("arquivo")
    p_yara.set_defaults(func=_cmd_yara)

    p_fz = sub.add_parser("fuzzy", help="hash ssdeep; com 2 arquivos, mostra a semelhança")
    p_fz.add_argument("arquivos", nargs="+", metavar="arquivo", help="1 ou 2 arquivos")
    p_fz.set_defaults(func=_cmd_fuzzy)

    p_scr = sub.add_parser("script", help="lista os indícios de um script e os pontos de cada um")
    p_scr.add_argument("arquivo")
    p_scr.set_defaults(func=_cmd_script)

    p_ent = sub.add_parser("entropia", help="desenha a entropia do arquivo, trecho por trecho")
    p_ent.add_argument("arquivo")
    p_ent.add_argument("--linhas", type=int, default=16, help="máximo de linhas do gráfico")
    p_ent.set_defaults(func=_cmd_entropia)

    p_ass = sub.add_parser("adicionar-assinatura", help="coloca o hash de um arquivo na base")
    p_ass.add_argument("arquivo")
    p_ass.add_argument("--nome", required=True, help="nome da ameaça (ex: Teste.Meu.Virus)")
    p_ass.add_argument("--fuzzy", action="store_true", help="grava a assinatura ssdeep (Aula 6) em vez do sha256")
    p_ass.set_defaults(func=_cmd_adicionar_assinatura)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 3
