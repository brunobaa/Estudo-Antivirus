"""Motor: Tipo real (magic bytes) (Aula 2).

A extensão (.jpg, .pdf) é só uma parte do NOME do arquivo, e qualquer um pode
trocar. O tipo verdadeiro está nos primeiros bytes do conteúdo, os "magic bytes".

    nome:     boleto.pdf             ──► diz que é PDF
    conteúdo: 4D 5A 90 00 ... ("MZ") ──► na verdade é um programa .exe  🚨

Este motor pega quatro truques:
  1. executável disfarçado ........ boleto.pdf que começa com "MZ"
  2. extensão dupla ............... foto.jpg.exe
  3. caractere de inversão (RLO) .. "fatura[RLO]fdp.exe" aparece como "faturaexe.pdf"
  4. compactado disfarçado ........ documento.pdf que na verdade é um .zip
"""

from __future__ import annotations

from dataclasses import dataclass

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.registro import registrar


@dataclass(frozen=True)
class TipoArquivo:
    nome: str
    magic: bytes
    categoria: str               # executavel, compactado, documento, imagem, midia
    extensoes: frozenset[str]
    deslocamento: int = 0        # onde a assinatura começa (quase sempre 0)
    extra: tuple[int, bytes] | None = None  # 2ª parte a conferir (ex: RIFF....WEBP)


def _tipo(nome, magic, categoria, extensoes, deslocamento=0, extra=None):
    return TipoArquivo(nome, magic, categoria, frozenset(extensoes.split()), deslocamento, extra)


# Ordem importa: as assinaturas mais específicas vêm antes das mais curtas.
TIPOS: list[TipoArquivo] = [
    # ── Executáveis ──────────────────────────────────────────────────────────
    _tipo("executável do Windows (PE)", b"MZ", "executavel",
          "exe dll sys scr ocx cpl drv efi com mui ax node"),
    _tipo("executável do Linux (ELF)", b"\x7fELF", "executavel", "elf so bin o out"),
    _tipo("executável do macOS (Mach-O)", b"\xcf\xfa\xed\xfe", "executavel", "dylib bundle"),
    _tipo("atalho do Windows (LNK)", b"\x4c\x00\x00\x00\x01\x14\x02\x00", "executavel", "lnk"),
    # ── Compactados ──────────────────────────────────────────────────────────
    _tipo("arquivo ZIP", b"PK\x03\x04", "compactado",
          "zip docx xlsx pptx jar apk odt ods odp epub xpi nupkg whl vsix ipa kmz 3mf"),
    _tipo("arquivo RAR", b"Rar!\x1a\x07", "compactado", "rar"),
    _tipo("arquivo 7-Zip", b"7z\xbc\xaf\x27\x1c", "compactado", "7z"),
    _tipo("arquivo GZIP", b"\x1f\x8b", "compactado", "gz tgz"),
    _tipo("arquivo CAB", b"MSCF", "compactado", "cab"),
    # ── Documentos ───────────────────────────────────────────────────────────
    _tipo("documento PDF", b"%PDF-", "documento", "pdf"),
    _tipo("documento Office antigo (OLE2)", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "documento",
          "doc xls ppt msi msg pub vsd"),
    # ── Imagens ──────────────────────────────────────────────────────────────
    _tipo("imagem PNG", b"\x89PNG\r\n\x1a\n", "imagem", "png"),
    _tipo("imagem JPEG", b"\xff\xd8\xff", "imagem", "jpg jpeg jfif jpe"),
    _tipo("imagem GIF", b"GIF87a", "imagem", "gif"),
    _tipo("imagem GIF", b"GIF89a", "imagem", "gif"),
    _tipo("imagem WEBP", b"RIFF", "imagem", "webp", extra=(8, b"WEBP")),
    _tipo("ícone do Windows", b"\x00\x00\x01\x00", "imagem", "ico"),
    _tipo("imagem BMP", b"BM", "imagem", "bmp dib"),
    # ── Áudio e vídeo ────────────────────────────────────────────────────────
    _tipo("áudio WAV", b"RIFF", "midia", "wav", extra=(8, b"WAVE")),
    _tipo("vídeo AVI", b"RIFF", "midia", "avi", extra=(8, b"AVI ")),
    _tipo("vídeo MP4/MOV", b"ftyp", "midia", "mp4 m4a m4v mov 3gp heic avif", deslocamento=4),
    _tipo("vídeo MKV/WEBM", b"\x1a\x45\xdf\xa3", "midia", "mkv webm"),
    _tipo("áudio MP3", b"ID3", "midia", "mp3"),
    _tipo("áudio OGG", b"OggS", "midia", "ogg oga ogv opus"),
    _tipo("áudio FLAC", b"fLaC", "midia", "flac"),
]

# Extensões que o Windows EXECUTA ao dar dois cliques
PERIGOSAS = frozenset(
    "exe scr com pif bat cmd ps1 vbs vbe js jse wsf wsh hta lnk msi msp cpl jar reg dll".split()
)

# Extensões "inocentes" que um atacante usa como isca no nome
ISCAS = frozenset(
    "jpg jpeg png gif bmp pdf doc docx xls xlsx ppt pptx txt rtf csv odt "
    "mp3 mp4 avi mov mkv zip rar".split()
)

# Caracteres invisíveis que mudam a direção do texto (Unicode "bidi")
INVERSORES = {
    "\u202e": "RLO", "\u202d": "LRO", "\u202b": "RLE", "\u202a": "LRE",
    "\u2066": "LRI", "\u2067": "RLI", "\u2068": "FSI", "\u200f": "RLM",
}

# Disfarces destas categorias são só "estranhos"; executáveis disfarçados são graves
CATEGORIAS_SUSPEITAS = {"compactado", "documento"}


def identificar(cabecalho: bytes) -> TipoArquivo | None:
    """Descobre o tipo real olhando os primeiros bytes."""
    for tipo in TIPOS:
        inicio, fim = tipo.deslocamento, tipo.deslocamento + len(tipo.magic)
        if cabecalho[inicio:fim] != tipo.magic:
            continue
        if tipo.extra:
            pos, valor = tipo.extra
            if cabecalho[pos:pos + len(valor)] != valor:
                continue
        return tipo
    return None


def extensoes(nome: str) -> tuple[str, str]:
    """Devolve (extensão final, extensão anterior).

    "foto.jpg.exe" → ("exe", "jpg")    "foto.jpg      .exe" → ("exe", "jpg")
    "relatorio.pdf" → ("pdf", "")       "LEIAME" → ("", "")
    """
    partes = [p.strip().lower() for p in nome.split(".")]
    if len(partes) < 2:
        return "", ""
    anterior = partes[-2] if len(partes) >= 3 else ""
    return partes[-1], anterior


def como_o_windows_mostra(nome: str) -> str:
    """Simula o efeito do RLO: tudo depois dele aparece de trás pra frente."""
    for caractere in ("\u202e", "\u202d"):
        if caractere in nome:
            antes, depois = nome.split(caractere, 1)
            return antes + depois[::-1]
    return nome


@registrar
class MotorTipo(Motor):
    id = "tipo"
    nome = "Tipo real (magic bytes)"
    aula = 2
    pronto = True

    def analisar(self, arquivo: Arquivo) -> Resultado:
        nome = arquivo.caminho.name

        # Truque 3: caractere invisível que inverte o nome
        achados = [sigla for c, sigla in INVERSORES.items() if c in nome]
        if achados:
            visivel = como_o_windows_mostra(nome).replace("\u202e", "").replace("\u202d", "")
            return Resultado.malicioso(
                f"nome tem caractere invisível de inversão ({', '.join(achados)}); "
                f"aparece como \"{visivel}\""
            )

        ext, isca = extensoes(nome)
        dupla = isca in ISCAS and ext in PERIGOSAS
        real = identificar(arquivo.cabecalho(64))

        # Truques 1 e 2 com conteúdo executável: o caso mais grave
        if real and real.categoria == "executavel":
            if ext in real.extensoes:
                if dupla:
                    return Resultado.malicioso(f"extensão dupla .{isca}.{ext} esconde um {real.nome}")
                return Resultado.limpo(f"{real.nome}, extensão confere")
            if ext == "":
                return Resultado.suspeito(f"{real.nome} sem extensão")
            return Resultado.malicioso(f"é um {real.nome} disfarçado de .{ext}")

        # Truque 2: extensão dupla com conteúdo que não é binário (ex: script .bat)
        if dupla:
            return Resultado.suspeito(
                f"extensão dupla: parece .{isca}, mas o Windows abre como .{ext}"
            )

        if real is None:
            return Resultado.limpo("sem magic bytes conhecidos (texto ou formato raro)")
        if ext in real.extensoes:
            return Resultado.limpo(f"{real.nome}, extensão confere")

        # Truque 4: compactado/documento com extensão de outra coisa
        rotulo_ext = f".{ext}" if ext else "(sem extensão)"
        if ext and real.categoria in CATEGORIAS_SUSPEITAS:
            return Resultado.suspeito(f"é um {real.nome} disfarçado de {rotulo_ext}")
        return Resultado.limpo(f"extensão {rotulo_ext}, mas o conteúdo é {real.nome}")
