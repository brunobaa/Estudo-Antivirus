"""Motor: Scripts e macros (Aula 7).

Scripts (.ps1, .js, .vbs, .bat, .hta...) são TEXTO: não têm cabeçalho PE, não
têm imports, e a entropia é baixa. Mesmo assim são um dos meios de ataque mais
usados, porque o Windows já traz os interpretadores (PowerShell, WScript).

O motor lê o texto e soma pontos por dois tipos de indício:

    1. O QUE o script usa ......... montar e executar código na hora,
                                    conteúdo codificado, janela escondida,
                                    download, objetos de sistema
    2. COMO ele está escrito ...... ofuscação: Base64 gigante, strings picotadas,
                                    caracteres por código, linhas enormes

    0 ───────────── 3 ──────────── 6 ──────────►
    ✅ normal       🟡 suspeito     🚨 vários sinais juntos

Macros em documentos Office antigos são cobertas pela regra YARA
Documento_Office_Com_Macro_Automatica (Aula 5).
"""

from __future__ import annotations

import re

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.pontuacao import Pontuacao, classificar
from superav.core.registro import registrar
from superav.motores.tipo import extensoes

EXTENSOES_SCRIPT = frozenset("ps1 psm1 psd1 js jse vbs vbe wsf wsh hta bat cmd".split())
LIMITE_LEITURA = 2 * 1024 * 1024  # scripts de verdade são pequenos

# Indicadores procurados no texto (em minúsculas). Cada um conta uma vez só.
# São os mesmos tipos de termo que ferramentas de defesa (AMSI, regras Sigma)
# observam. Nenhum deles é proibido sozinho: o que pesa é a SOMA.
#            grupo          termo                   pontos  explicação
INDICADORES = [
    ("execução",  "invoke-expression",       2, "executa texto como código (PowerShell)"),
    ("execução",  "eval(",                   2, "executa texto como código (JavaScript)"),
    ("execução",  "executeglobal",           2, "executa texto como código (VBScript)"),
    ("codificado", "-encodedcommand",        3, "comando PowerShell codificado em Base64"),
    ("codificado", "frombase64string",       2, "decodifica Base64 em tempo de execução"),
    ("download",  "downloadstring",          2, "baixa conteúdo da internet"),
    ("download",  "downloadfile",            2, "baixa arquivo da internet"),
    ("download",  "net.webclient",           1, "cliente web do .NET"),
    ("download",  "msxml2.xmlhttp",          2, "requisição web a partir de script"),
    ("download",  "bitsadmin",               2, "transferência em segundo plano (BITS)"),
    ("esconder",  "-windowstyle hidden",     2, "abre o PowerShell com a janela escondida"),
    ("esconder",  "-executionpolicy bypass", 2, "desliga a política de execução de scripts"),
    ("esconder",  "-noprofile",              1, "ignora o perfil do usuário"),
    ("sistema",   "wscript.shell",           2, "objeto que roda comandos do sistema"),
    ("sistema",   "shell.application",       2, "objeto que controla o Explorer"),
    ("sistema",   "mshta",                   2, "executa aplicativo HTML (.hta)"),
    ("sistema",   "activexobject",           1, "cria objetos COM a partir de JavaScript"),
    ("ofuscação", "fromcharcode",            2, "monta texto a partir de códigos numéricos"),
    ("ofuscação", "unescape(",               1, "desfaz codificação de texto"),
]

# Termos curtos são procurados como PALAVRA inteira, para "iex" não casar
# dentro de outra palavra qualquer
PALAVRAS = [
    ("execução",  "iex",  2, "apelido de Invoke-Expression"),
    ("codificado", "-enc", 3, "abreviação de -EncodedCommand"),
]

SEPARADORES = re.compile("[^a-z0-9_.-]+")
BASE64_LONGO = re.compile("[A-Za-z0-9+/]{200,}={0,2}")
# In`vo`ke: o PowerShell ignora a crase. O (?=...) confere a letra seguinte sem
# "consumi-la", para W`r`i`t`e contar 4 crases (sem ele, findall pula pares)
CRASE_NO_MEIO = re.compile("[a-z]`(?=[a-z])")


def decodificar(dados: bytes) -> str:
    """Bytes → texto. Scripts do Windows muitas vezes estão em UTF-16."""
    if dados.startswith((b"\xff\xfe", b"\xfe\xff")):
        return dados.decode("utf-16", errors="replace")
    if dados[:1000].count(b"\x00") > len(dados[:1000]) // 3:  # UTF-16 sem BOM
        return dados.decode("utf-16-le", errors="replace")
    return dados.decode("utf-8-sig", errors="replace")


def analisar_texto(texto: str) -> Pontuacao:
    """Soma os indícios de um script. Separado do motor para testar fácil."""
    p = Pontuacao()
    minusculo = texto.lower()
    palavras = set(SEPARADORES.split(minusculo))
    grupos = set()

    # 1. O QUE o script usa
    for grupo, termo, pontos, explicacao in INDICADORES:
        if termo in minusculo:
            p.marcar(pontos, f"{termo}: {explicacao}")
            grupos.add(grupo)
    for grupo, termo, pontos, explicacao in PALAVRAS:
        if termo in palavras:
            p.marcar(pontos, f"{termo}: {explicacao}")
            grupos.add(grupo)

    if "download" in grupos and grupos & {"execução", "codificado"}:
        p.marcar(2, "combinação: baixa algo da internet E executa código montado na hora")

    # 2. COMO ele está escrito
    blocos = BASE64_LONGO.findall(texto)
    if blocos:
        p.marcar(2, f"bloco Base64 de {max(map(len, blocos))} caracteres")

    maior_linha = max((len(l) for l in texto.splitlines()), default=0)
    if maior_linha > 1000:
        p.marcar(1, f"linha com {maior_linha} caracteres")

    pedacos = sum(minusculo.count(s) for s in ('" + "', "' + '", '"+"', "'+'", '" & "', '"&"'))
    if pedacos >= 20:
        p.marcar(2, f"texto picotado em {pedacos} pedaços concatenados")

    por_codigo = minusculo.count("[char]") + minusculo.count("chr(")
    if por_codigo >= 10:
        p.marcar(2, f"{por_codigo} caracteres montados por código numérico")

    crases = len(CRASE_NO_MEIO.findall(minusculo))
    if crases >= 5:
        p.marcar(2, f"{crases} crases no meio de palavras (ofuscação de PowerShell)")

    circunflexos = sum(
        1 for i in range(1, len(minusculo) - 1)
        if minusculo[i] == "^" and minusculo[i - 1].isalpha() and minusculo[i + 1].isalpha()
    )
    if circunflexos >= 5:
        p.marcar(2, f"{circunflexos} circunflexos no meio de palavras (ofuscação de .bat)")

    return p


def e_script(nome: str) -> bool:
    ext, _ = extensoes(nome)
    return ext in EXTENSOES_SCRIPT


@registrar
class MotorScripts(Motor):
    id = "scripts"
    nome = "Scripts e macros"
    aula = 7
    pronto = True

    def analisar(self, arquivo: Arquivo) -> Resultado:
        if not e_script(arquivo.caminho.name):
            return Resultado.limpo("não é um script")
        texto = decodificar(arquivo.dados[:LIMITE_LEITURA])
        return classificar(analisar_texto(texto), sem_sinais="script sem indícios")
