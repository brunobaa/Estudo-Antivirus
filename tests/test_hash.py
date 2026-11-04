"""Testes do motor de hash (Aula 1).

Rodar: python -m unittest discover tests
"""

import hashlib
import tempfile
import unittest
from pathlib import Path

from superav.core.motor import Arquivo, Veredito
from superav.motores.hash import MotorHash, carregar_base, interpretar_linha

RAIZ = Path(__file__).resolve().parent.parent


class TesteHashDoArquivo(unittest.TestCase):
    def setUp(self):
        self.pasta = Path(tempfile.mkdtemp())
        self.caminho = self.pasta / "a.bin"
        self.conteudo = b"ola mundo"
        self.caminho.write_bytes(self.conteudo)

    def test_bate_com_hashlib(self):
        arq = Arquivo(self.caminho)
        for alg in ("md5", "sha1", "sha256"):
            self.assertEqual(arq.hash(alg), hashlib.new(alg, self.conteudo).hexdigest())

    def test_arquivo_maior_que_um_bloco(self):
        grande = bytes(range(256)) * 10_000  # ~2,5 MB: mais de um bloco de 1 MB
        self.caminho.write_bytes(grande)
        self.assertEqual(Arquivo(self.caminho).hash(), hashlib.sha256(grande).hexdigest())

    def test_efeito_avalanche(self):
        h1 = Arquivo(self.caminho).hash()
        self.caminho.write_bytes(b"ola mundO")  # muda UMA letra
        h2 = Arquivo(self.caminho).hash()
        iguais = sum(a == b for a, b in zip(h1, h2))
        self.assertNotEqual(h1, h2)
        self.assertLess(iguais, 16)  # sobram só coincidências (~1/16 por caractere)


class TesteBase(unittest.TestCase):
    def test_interpretar_linha(self):
        sha = "a" * 64
        self.assertEqual(interpretar_linha(f"{sha}  Trojan.X"), ("sha256", sha, "Trojan.X"))
        self.assertEqual(interpretar_linha("B" * 32 + " Worm.Y"), ("md5", "b" * 32, "Worm.Y"))
        self.assertEqual(interpretar_linha("c" * 40)[0], "sha1")
        self.assertEqual(interpretar_linha("c" * 40)[2], "Malware.SemNome")

    def test_linhas_ignoradas(self):
        for linha in ["", "   ", "# comentario", "xyz Nao.E.Hash", "g" * 64 + " Nao.E.Hex", "a" * 50]:
            self.assertIsNone(interpretar_linha(linha), linha)

    def test_comentario_no_fim_da_linha(self):
        self.assertEqual(interpretar_linha("a" * 64 + " Virus.Z  # visto em 2026")[2], "Virus.Z")

    def test_base_oficial_tem_eicar(self):
        base = carregar_base()
        eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        self.assertEqual(base["sha256"][eicar], "EICAR-Test-File")


class TesteMotorHash(unittest.TestCase):
    def setUp(self):
        self.pasta = Path(tempfile.mkdtemp())
        self.virus = self.pasta / "virus.txt"
        self.virus.write_bytes(b"conteudo malvado de mentira")
        self.limpo = self.pasta / "limpo.txt"
        self.limpo.write_bytes(b"conteudo bom")

        self.base = self.pasta / "base"
        self.base.mkdir()
        sha = hashlib.sha256(self.virus.read_bytes()).hexdigest()
        (self.base / "a.txt").write_text(f"# teste\n{sha}  Teste.Malvado\n", encoding="utf-8")

    def test_detecta_por_sha256(self):
        r = MotorHash(self.base).analisar(Arquivo(self.virus))
        self.assertEqual(r.veredito, Veredito.MALICIOSO)
        self.assertIn("Teste.Malvado", r.detalhe)

    def test_detecta_por_md5(self):
        md5 = hashlib.md5(self.limpo.read_bytes()).hexdigest()
        (self.base / "b.txt").write_text(f"{md5}  Antigo.PorMD5\n", encoding="utf-8")
        r = MotorHash(self.base).analisar(Arquivo(self.limpo))
        self.assertEqual(r.veredito, Veredito.MALICIOSO)
        self.assertIn("md5", r.detalhe)

    def test_arquivo_limpo_passa(self):
        r = MotorHash(self.base).analisar(Arquivo(self.limpo))
        self.assertEqual(r.veredito, Veredito.LIMPO)

    def test_um_byte_a_mais_escapa(self):
        # A grande fraqueza do hash: mudou 1 byte, a assinatura não pega mais
        self.virus.write_bytes(self.virus.read_bytes() + b" ")
        r = MotorHash(self.base).analisar(Arquivo(self.virus))
        self.assertEqual(r.veredito, Veredito.LIMPO)

    def test_amostra_do_repositorio_e_detectada(self):
        r = MotorHash().analisar(Arquivo(RAIZ / "amostras" / "teste" / "falso-virus.txt"))
        self.assertEqual(r.veredito, Veredito.MALICIOSO)
        self.assertIn("Teste.SuperAV.FalsoVirus", r.detalhe)


if __name__ == "__main__":
    unittest.main()
