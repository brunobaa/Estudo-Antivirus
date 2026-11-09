"""Testes do motor YARA (Aula 5).

Rodar: python -m unittest discover tests
"""

import tempfile
import unittest
from pathlib import Path

from superav.core.motor import Arquivo, Veredito
from superav.motores.hash import MotorHash
from superav.motores.yara import MotorYara, compilar, yara

RAIZ = Path(__file__).resolve().parent.parent
AMOSTRAS = RAIZ / "amostras"

REGRA_TESTE = """
rule Teste_Duas_Palavras
{
    meta:
        severidade = "malicioso"
    strings:
        $a = "banana" nocase
        $b = "abacaxi"
    condition:
        all of them
}

rule Teste_Sem_Severidade
{
    strings:
        $x = "kiwi"
    condition:
        $x
}
"""


@unittest.skipUnless(yara, "precisa do yara-python")
class TesteRegrasProprias(unittest.TestCase):
    def setUp(self):
        self.pasta = Path(tempfile.mkdtemp())
        self.regras = self.pasta / "regras"
        self.regras.mkdir()
        (self.regras / "frutas.yar").write_text(REGRA_TESTE, encoding="utf-8")

    def analisar(self, conteudo, pasta_regras=None):
        caminho = self.pasta / "alvo.txt"
        caminho.write_bytes(conteudo)
        return MotorYara(pasta_regras or self.regras).analisar(Arquivo(caminho))

    def test_todas_as_strings(self):
        r = self.analisar(b"comprei BANANA e abacaxi na feira")
        self.assertEqual(r.veredito, Veredito.MALICIOSO)
        self.assertIn("Teste_Duas_Palavras", r.detalhe)

    def test_condicao_nao_satisfeita(self):
        # Só uma das duas strings: "all of them" não casa
        self.assertEqual(self.analisar(b"so banana aqui").veredito, Veredito.LIMPO)

    def test_sem_nocase_diferencia_maiusculas(self):
        self.assertEqual(self.analisar(b"banana e ABACAXI").veredito, Veredito.LIMPO)

    def test_severidade_padrao_e_suspeito(self):
        self.assertEqual(self.analisar(b"um kiwi").veredito, Veredito.SUSPEITO)

    def test_regra_quebrada_vira_erro_e_nao_derruba(self):
        (self.regras / "quebrada.yar").write_text("rule Quebrada { condition: $nao_existe }", encoding="utf-8")
        r = self.analisar(b"qualquer coisa")
        self.assertEqual(r.veredito, Veredito.ERRO)
        self.assertIn("regra com erro", r.detalhe)

    def test_pasta_sem_regras(self):
        vazia = self.pasta / "vazia"
        vazia.mkdir()
        r = self.analisar(b"qualquer coisa", vazia)
        self.assertEqual(r.veredito, Veredito.LIMPO)
        self.assertIn("nenhuma regra", r.detalhe)

    def test_caminho_com_acento(self):
        # Regressão: o YARA em C não abria "Área de Trabalho" no Windows
        com_acento = self.pasta / "Área de Ação"
        com_acento.mkdir()
        (com_acento / "frutas.yar").write_text(REGRA_TESTE, encoding="utf-8")
        regras, total = compilar(com_acento)
        self.assertEqual(total, 2)


@unittest.skipUnless(yara, "precisa do yara-python")
class TesteRegrasDoProjeto(unittest.TestCase):
    def setUp(self):
        self.motor = MotorYara()

    def test_regras_do_projeto_compilam(self):
        self.assertIsNone(self.motor.erro)
        self.assertGreaterEqual(self.motor.total, 5)

    def test_amostras(self):
        esperado = {
            "teste/falso-virus.txt": (Veredito.MALICIOSO, "SuperAV_FalsoVirus"),
            "teste/nota-de-resgate.txt": (Veredito.MALICIOSO, "Nota_De_Resgate"),
            "teste/boleto.pdf": (Veredito.SUSPEITO, "Executavel_Pequeno_Demais"),
            "limpos/ola.txt": (Veredito.LIMPO, ""),
            "limpos/texto-longo.txt": (Veredito.LIMPO, ""),
        }
        for nome, (veredito, regra) in esperado.items():
            r = self.motor.analisar(Arquivo(AMOSTRAS / nome))
            self.assertEqual(r.veredito, veredito, nome)
            self.assertIn(regra, r.detalhe, nome)

    def test_yara_pega_variante_que_o_hash_perde(self):
        # A grande lição da aula: muda 1 byte → o hash não reconhece mais,
        # mas a regra YARA continua achando os padrões dentro do arquivo
        variante = Path(tempfile.mkdtemp()) / "variante.txt"
        variante.write_bytes((AMOSTRAS / "teste" / "falso-virus.txt").read_bytes() + b" ")
        self.assertEqual(MotorHash().analisar(Arquivo(variante)).veredito, Veredito.LIMPO)
        self.assertEqual(self.motor.analisar(Arquivo(variante)).veredito, Veredito.MALICIOSO)

    def test_nota_de_resgate_precisa_de_3_frases(self):
        artigo = Path(tempfile.mkdtemp()) / "noticia.txt"
        # Uma notícia sobre bitcoin não é nota de resgate (só 1 dos padrões)
        artigo.write_bytes(b"O preco do bitcoin subiu muito esta semana segundo analistas.")
        self.assertEqual(self.motor.analisar(Arquivo(artigo)).veredito, Veredito.LIMPO)


if __name__ == "__main__":
    unittest.main()
