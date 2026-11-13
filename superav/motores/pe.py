"""Motor: Estrutura PE (.exe) (Aula 4).

PE = "Portable Executable", o formato dos .exe e .dll do Windows. Em vez de
olhar o arquivo como um monte de bytes, este motor o abre pela ESTRUTURA:
cabeçalhos, seções e a tabela de funções que o programa importa do sistema.

A ideia não é afirmar "isto é um vírus", e sim somar INDÍCIOS. Cada sinal
estranho vale alguns pontos; a soma vira o veredito:

    0 ───────────── 3 ──────────── 6 ──────────►
    ✅ normal       🟡 suspeito     🚨 vários sinais juntos

Precisa da biblioteca `pefile` (pip install pefile). Sem ela, o motor fica
pendente em vez de quebrar o programa.
"""

from __future__ import annotations

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.pontuacao import Pontuacao
from superav.core.pontuacao import classificar as classificar_pontuacao
from superav.core.registro import registrar

try:
    import pefile
except ImportError:
    pefile = None

# Funções da API do Windows que, JUNTAS, formam a receita de injetar código em
# outro processo. Programas normais quase nunca usam todas essas ao mesmo tempo.
# (Conhecer os nomes é defesa: é o que um analista procura num executável suspeito.)
API_INJECAO = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
}
API_CARGA_DINAMICA = {"LoadLibraryA", "LoadLibraryW", "GetProcAddress"}
API_ESPIONAGEM = {
    "SetWindowsHookExA", "SetWindowsHookExW",  # capturar teclado (keylogger)
    "GetAsyncKeyState", "GetKeyState", "BitBlt",  # teclado e tela
}
API_ANTIANALISE = {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA"}

# Nomes de seção que fogem do padrão .text/.data/.rdata/.rsrc/... e costumam
# ser deixados por empacotadores (packers).
SECOES_CONHECIDAS = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata",
    ".rsrc", ".reloc", ".tls", ".debug", ".didat", ".xdata", ".00cfg",
    ".gfids", ".voltbl", ".sxdata", "fothk",
}
SECOES_DE_PACKER = {
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "ASPack", ".nsp0",
    "FSG!", ".petite", ".Themida", ".vmp0", ".vmp1", ".enigma1",
}


# A pontuação agora mora no núcleo (core/pontuacao.py), porque o motor de
# scripts (Aula 7) usa a mesma ideia. O nome antigo continua valendo.
AnalisePE = Pontuacao


def avaliar_imports(nomes: set[str], analise: AnalisePE) -> None:
    """Pontua a tabela de imports. Recebe o conjunto de nomes de função."""
    injecao = nomes & API_INJECAO
    if len(injecao) >= 2:
        analise.marcar(4, f"injeção de código em outro processo: {', '.join(sorted(injecao))}")
    elif injecao:
        analise.marcar(1, f"função de manipulação de memória: {', '.join(injecao)}")

    if nomes & API_ESPIONAGEM:
        analise.marcar(3, f"captura de teclado/tela: {', '.join(sorted(nomes & API_ESPIONAGEM))}")

    if API_CARGA_DINAMICA <= nomes and len(nomes) < 15:
        # Poucas funções visíveis + carga dinâmica = resto do código fica escondido
        analise.marcar(2, "quase só LoadLibrary/GetProcAddress: imports escondidos em tempo de execução")

    if nomes & API_ANTIANALISE:
        analise.marcar(1, f"checa se está sendo depurado: {', '.join(sorted(nomes & API_ANTIANALISE))}")


def avaliar_secoes(secoes: list[tuple[str, float]], analise: AnalisePE) -> None:
    """Pontua as seções. Recebe lista de (nome, entropia)."""
    nomes = {nome for nome, _ in secoes}

    packers = {n for n in nomes if n in SECOES_DE_PACKER or n.upper().startswith("UPX")}
    if packers:
        analise.marcar(3, f"seção de empacotador (packer): {', '.join(sorted(packers))}")

    estranhas = {n for n in nomes if n and n not in SECOES_CONHECIDAS and n not in packers}
    if estranhas:
        analise.marcar(1, f"seção com nome fora do padrão: {', '.join(sorted(estranhas))}")

    for nome, entropia in secoes:
        if entropia >= 7.2 and nome in {".text", ".code"}:
            analise.marcar(2, f"seção de código {nome} parece cifrada/comprimida (entropia {entropia:.1f})")


def classificar(analise: AnalisePE) -> Resultado:
    return classificar_pontuacao(analise, sem_sinais="estrutura PE normal")


@registrar
class MotorPE(Motor):
    id = "pe"
    nome = "Estrutura PE (.exe)"
    aula = 4
    pronto = pefile is not None

    def analisar(self, arquivo: Arquivo) -> Resultado:
        if arquivo.cabecalho(2) != b"MZ":
            return Resultado.limpo("não é um executável do Windows")

        try:
            pe = pefile.PE(data=arquivo.dados, fast_load=True)
        except Exception as erro:
            # Um PE que nem abre, sendo que começa com MZ, já é estranho
            return Resultado.suspeito(f"cabeçalho PE quebrado: {type(erro).__name__}")

        analise = AnalisePE()

        # Seções: nome + entropia de cada uma (o pefile calcula a entropia)
        secoes = []
        for s in pe.sections:
            nome = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
            secoes.append((nome, s.get_entropy()))
            flags = s.Characteristics
            if (flags & 0x20000000) and (flags & 0x80000000):  # executável E gravável
                analise.marcar(2, f"seção {nome} é executável e gravável ao mesmo tempo")
        analise.resumo["secoes"] = secoes
        avaliar_secoes(secoes, analise)

        # Imports: nomes de todas as funções importadas
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        nomes = set()
        for dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in dll.imports:
                if imp.name:
                    nomes.add(imp.name.decode("latin-1", "replace"))
        analise.resumo["qtd_imports"] = len(nomes)
        analise.resumo["qtd_dlls"] = len(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))

        if not nomes and not getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            analise.marcar(2, "nenhum import visível (código provavelmente empacotado)")
        avaliar_imports(nomes, analise)

        pe.close()
        return classificar(analise)
