"""Testes do motor de entropia (Aula 3).

Rodar: python -m unittest discover tests
"""

import base64
import random
import tempfile
import unittest
import zlib
from pathlib import Path

from superav.core.motor import Arquivo, Veredito
from superav.motores.entropia import MotorEntropia, entropia, medir

RAIZ = Path(__file__).resolve().parent.parent
ALEATORIO = random.Random(42).randbytes(16 * 1024)
TEXTO = ("Era uma vez um antivirus que media a entropia dos arquivos. " * 40).encode()


class TesteFormula(unittest.TestCase):
    def test_extremos(self):
        self.assertEqual(entropia(b""), 0.0)
        self.assertEqual(entropia(b"AAAAAAAA"), 0.0)               # nenhuma surpresa
        self.assertAlmostEqual(entropia(bytes(range(256))), 8.0)   # todos iguais = máximo

    def test_exemplos_da_aula(self):
        self.assertAlmostEqual(entropia(b"ABABABAB"), 1.0)         # 2 símbolos = 1 bit
        self.assertAlmostEqual(entropia(b"ABCD"), 2.0)             # 4 símbolos = 2 bits
        self.assertAlmostEqual(entropia(b"AAAB"), 0.811, places=3)

    def test_ordem_nao_importa(self):
        # Entropia só olha QUANTAS vezes cada byte aparece, não a ordem
        self.assertEqual(entropia(b"AABB"), entropia(b"ABAB"))

    def test_texto_aleatorio_e_compactado(self):
        self.assertLess(entropia(TEXTO), 5.0)
        self.assertGreater(entropia(ALEATORIO), 7.9)
        self.assertGreater(entropia(zlib.compress(ALEATORIO + TEXTO)), 7.5)

    def test_base64_nunca_passa_de_6(self):
        # Base64 usa só 64 símbolos: log2(64) = 6. Uma forma de "esconder" dados cifrados
        self.assertLessEqual(entropia(base64.b64encode(ALEATORIO)), 6.0)

    def test_medir_soma_blocos(self):
        m = medir(TEXTO + ALEATORIO, tamanho_bloco=1024)
        self.assertEqual(m.analisados, len(TEXTO) + len(ALEATORIO))
        self.assertAlmostEqual(m.geral, entropia(TEXTO + ALEATORIO))
        self.assertLess(m.blocos[0], 5.0)       # começo: texto
        # fim: aleatório. Usa o PENÚLTIMO bloco: o último é um pedaço pequeno, e
        # poucos bytes não conseguem mostrar os 256 valores (entropia sai menor)
        self.assertGreater(m.blocos[-2], 7.5)
        self.assertLess(m.blocos[-1], m.blocos[-2])
        self.assertGreater(m.fracao_alta, 0.5)


class TesteMotorEntropia(unittest.TestCase):
    def setUp(self):
        self.pasta = Path(tempfile.mkdtemp())
        self.motor = MotorEntropia()

    def analisar(self, nome, conteudo):
        caminho = self.pasta / nome
        caminho.write_bytes(conteudo)
        return self.motor.analisar(Arquivo(caminho))

    def test_arquivo_pequeno_nao_e_medido(self):
        r = self.analisar("x.bin", ALEATORIO[:100])
        self.assertEqual(r.veredito, Veredito.LIMPO)
        self.assertIn("pequeno", r.detalhe)

    def test_texto_cifrado_e_suspeito(self):
        self.assertEqual(self.analisar("relatorio.txt", ALEATORIO).veredito, Veredito.SUSPEITO)

    def test_texto_normal_passa(self):
        self.assertEqual(self.analisar("relatorio.txt", TEXTO).veredito, Veredito.LIMPO)

    def test_executavel_empacotado_e_suspeito(self):
        r = self.analisar("app.exe", b"MZ" + b"\x00" * 62 + ALEATORIO)
        self.assertEqual(r.veredito, Veredito.SUSPEITO)
        self.assertIn("packer", r.detalhe)

    def test_executavel_normal_passa(self):
        # Um pedaço aleatório pequeno (ex: um ícone) não basta para acusar
        r = self.analisar("app.exe", b"MZ" + b"\x00" * 62 + TEXTO * 10 + ALEATORIO[:4096])
        self.assertEqual(r.veredito, Veredito.LIMPO)

    def test_formatos_compactados_podem_ter_entropia_alta(self):
        for nome, cabecalho in [("a.zip", b"PK\x03\x04"), ("a.png", b"\x89PNG\r\n\x1a\n"),
                                ("a.jpg", b"\xff\xd8\xff\xe0")]:
            r = self.analisar(nome, cabecalho + ALEATORIO)
            self.assertEqual(r.veredito, Veredito.LIMPO, nome)
            self.assertIn("normal para", r.detalhe)

    def test_amostras_do_repositorio(self):
        esperado = {
            "teste/segredo.txt": Veredito.SUSPEITO,
            "teste/empacotado.exe": Veredito.SUSPEITO,
            "limpos/fotos.zip": Veredito.LIMPO,
            "limpos/texto-longo.txt": Veredito.LIMPO,
        }
        for nome, veredito in esperado.items():
            r = self.motor.analisar(Arquivo(RAIZ / "amostras" / nome))
            self.assertEqual(r.veredito, veredito, nome)


if __name__ == "__main__":
    unittest.main()
