"""Testes do motor de tipo real / magic bytes (Aula 2).

Rodar: python -m unittest discover tests
"""

import tempfile
import unittest
from pathlib import Path

from superav.core.motor import Arquivo, Veredito
from superav.motores.tipo import MotorTipo, como_o_windows_mostra, extensoes, identificar

RAIZ = Path(__file__).resolve().parent.parent
RLO = chr(0x202E)  # escrito assim de propósito: o caractere em si é invisível

MZ = b"MZ\x90\x00" + b"\x00" * 60
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
ZIP = b"PK\x03\x04" + b"\x00" * 20


class TesteIdentificar(unittest.TestCase):
    def test_tipos_comuns(self):
        casos = {
            MZ: "executável do Windows (PE)",
            b"\x7fELF\x02\x01": "executável do Linux (ELF)",
            PNG: "imagem PNG",
            b"\xff\xd8\xff\xe0\x00\x10JFIF": "imagem JPEG",
            b"GIF89a....": "imagem GIF",
            b"%PDF-1.7\n": "documento PDF",
            ZIP: "arquivo ZIP",
            b"Rar!\x1a\x07\x01\x00": "arquivo RAR",
        }
        for cabecalho, esperado in casos.items():
            self.assertEqual(identificar(cabecalho).nome, esperado)

    def test_assinatura_fora_do_inicio(self):
        # MP4: os 4 primeiros bytes são um tamanho; "ftyp" vem na posição 4
        self.assertEqual(identificar(b"\x00\x00\x00\x20ftypisom").nome, "vídeo MP4/MOV")

    def test_riff_precisa_da_segunda_parte(self):
        self.assertEqual(identificar(b"RIFF\x00\x00\x00\x00WEBPVP8 ").nome, "imagem WEBP")
        self.assertEqual(identificar(b"RIFF\x00\x00\x00\x00WAVEfmt ").nome, "áudio WAV")
        self.assertIsNone(identificar(b"RIFF\x00\x00\x00\x00XXXX"))

    def test_texto_nao_tem_magic(self):
        self.assertIsNone(identificar(b"ola mundo"))
        self.assertIsNone(identificar(b""))


class TesteNome(unittest.TestCase):
    def test_extensoes(self):
        self.assertEqual(extensoes("foto.jpg.exe"), ("exe", "jpg"))
        self.assertEqual(extensoes("FOTO.JPG.EXE"), ("exe", "jpg"))
        self.assertEqual(extensoes("foto.jpg          .exe"), ("exe", "jpg"))
        self.assertEqual(extensoes("relatorio.pdf"), ("pdf", ""))
        self.assertEqual(extensoes("LEIAME"), ("", ""))

    def test_efeito_do_rlo(self):
        self.assertEqual(como_o_windows_mostra(f"fatura{RLO}fdp.exe"), "faturaexe.pdf")


class TesteMotorTipo(unittest.TestCase):
    def setUp(self):
        self.pasta = Path(tempfile.mkdtemp())
        self.motor = MotorTipo()

    def analisar(self, nome, conteudo):
        caminho = self.pasta / nome
        caminho.write_bytes(conteudo)
        return self.motor.analisar(Arquivo(caminho))

    def test_executavel_disfarcado(self):
        r = self.analisar("boleto.pdf", MZ)
        self.assertEqual(r.veredito, Veredito.MALICIOSO)
        self.assertIn("disfarçado de .pdf", r.detalhe)

    def test_extensao_dupla_com_executavel(self):
        r = self.analisar("foto.jpg.exe", MZ)
        self.assertEqual(r.veredito, Veredito.MALICIOSO)
        self.assertIn(".jpg.exe", r.detalhe)

    def test_extensao_dupla_com_espacos(self):
        r = self.analisar("foto.jpg          .exe", MZ)
        self.assertEqual(r.veredito, Veredito.MALICIOSO)

    def test_extensao_dupla_de_script(self):
        r = self.analisar("ferias.mp4.bat", b"@echo off\r\n")
        self.assertEqual(r.veredito, Veredito.SUSPEITO)

    def test_rlo_no_nome(self):
        r = self.analisar(f"fatura{RLO}fdp.exe", MZ)
        self.assertEqual(r.veredito, Veredito.MALICIOSO)
        self.assertIn("faturaexe.pdf", r.detalhe)

    def test_zip_disfarcado_e_suspeito(self):
        self.assertEqual(self.analisar("documento.pdf", ZIP).veredito, Veredito.SUSPEITO)

    def test_imagem_com_extensao_trocada_nao_e_grave(self):
        # PNG salvo como .jpg acontece muito por engano: só informa
        r = self.analisar("foto.jpg", PNG)
        self.assertEqual(r.veredito, Veredito.LIMPO)
        self.assertIn("imagem PNG", r.detalhe)

    def test_arquivos_honestos_passam(self):
        for nome, conteudo in [("programa.exe", MZ), ("foto.png", PNG),
                               ("planilha.xlsx", ZIP), ("notas.txt", b"ola"),
                               ("backup.tar.gz", b"\x1f\x8b\x08\x00")]:
            self.assertEqual(self.analisar(nome, conteudo).veredito, Veredito.LIMPO, nome)

    def test_executavel_sem_extensao(self):
        self.assertEqual(self.analisar("programa", MZ).veredito, Veredito.SUSPEITO)

    def test_amostras_do_repositorio(self):
        esperado = {
            "boleto.pdf": Veredito.MALICIOSO,
            "foto.jpg.exe": Veredito.MALICIOSO,
            "documento.pdf": Veredito.SUSPEITO,
            "imagem.png": Veredito.LIMPO,
            "falso-virus.txt": Veredito.LIMPO,
        }
        for nome, veredito in esperado.items():
            r = self.motor.analisar(Arquivo(RAIZ / "amostras" / "teste" / nome))
            self.assertEqual(r.veredito, veredito, nome)


if __name__ == "__main__":
    unittest.main()
