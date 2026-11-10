"""Testes do motor de hash por semelhança / fuzzy hashing (Aula 6).

Rodar: python -m unittest discover tests
"""

import random
import string
import tempfile
import unittest
from pathlib import Path

from superav.core.motor import Arquivo, Veredito
from superav.motores.fuzzy import MotorFuzzy, carregar_base, mais_parecido, ppdeep
from superav.motores.hash import MotorHash
from superav.motores.yara import MotorYara

AMOSTRAS = Path(__file__).resolve().parent.parent / "amostras"
V1 = AMOSTRAS / "teste" / "familia-v1.txt"
V2 = AMOSTRAS / "teste" / "familia-v2.txt"


def texto(semente, tamanho=12000):
    # Letras e espaços aleatórios (semente fixa). Um vocabulário pequeno e
    # repetitivo NÃO serve: o ssdeep quase não acha pontos de corte nele, e a
    # nota pula de 100 direto para 0. Descobrimos isso escrevendo estes testes.
    rnd = random.Random(semente)
    return "".join(rnd.choice(string.ascii_lowercase + "     \n") for _ in range(tamanho)).encode()


def trocar_meio(original, outro, fracao):
    """Troca `fracao` do MEIO do original por um pedaço de outro texto."""
    n = int(len(original) * fracao)
    inicio = len(original) // 2 - n // 2
    return original[:inicio] + outro[:n] + original[inicio + n:]


@unittest.skipUnless(ppdeep, "precisa do ppdeep")
class TesteSsdeep(unittest.TestCase):
    def test_formato_do_hash(self):
        bloco, h1, h2 = ppdeep.hash(texto(1)).split(":")
        self.assertTrue(bloco.isdigit())
        self.assertTrue(h1 and h2)

    def test_identicos_dao_100(self):
        h = ppdeep.hash(texto(1))
        self.assertEqual(ppdeep.compare(h, h), 100)

    def test_pequena_mudanca_continua_parecido(self):
        original = texto(1)
        mudado = original[:3000] + b"UM TRECHO NOVO NO MEIO" + original[3000:]
        self.assertGreaterEqual(ppdeep.compare(ppdeep.hash(original), ppdeep.hash(mudado)), 80)

    def test_quanto_mais_muda_menor_a_nota(self):
        original, outro = texto(1), texto(9)
        notas = [ppdeep.compare(ppdeep.hash(original), ppdeep.hash(trocar_meio(original, outro, f)))
                 for f in (0.1, 0.3, 0.5)]
        self.assertEqual(notas, sorted(notas, reverse=True))  # diminui aos poucos
        self.assertGreater(notas[-1], 0)                         # mas não despenca a zero

    def test_textos_diferentes_dao_quase_zero(self):
        self.assertLess(ppdeep.compare(ppdeep.hash(texto(1)), ppdeep.hash(texto(2))), 30)


@unittest.skipUnless(ppdeep, "precisa do ppdeep")
class TesteBase(unittest.TestCase):
    def test_base_do_projeto(self):
        nomes = [nome for _, nome in carregar_base()]
        self.assertIn("Teste.SuperAV.Familia", nomes)

    def test_linhas_invalidas_e_comentarios(self):
        pasta = Path(tempfile.mkdtemp())
        (pasta / "a.ssdeep").write_text(
            "# comentario\n\nnao-e-hash Nome.Ruim\n3:abc:def  Familia.Boa\n6:xyz:uvw\n",
            encoding="utf-8",
        )
        self.assertEqual(carregar_base(pasta), [("3:abc:def", "Familia.Boa"), ("6:xyz:uvw", "Familia.SemNome")])

    def test_le_todos_os_ssdeep_da_pasta(self):
        pasta = Path(tempfile.mkdtemp())
        (pasta / "a.ssdeep").write_text("3:aaa:bbb  A\n", encoding="utf-8")
        (pasta / "b.ssdeep").write_text("3:ccc:ddd  B\n", encoding="utf-8")
        (pasta / "c.txt").write_text("3:eee:fff  C\n", encoding="utf-8")  # .txt é do motor de hash
        self.assertEqual([n for _, n in carregar_base(pasta)], ["A", "B"])

    def test_mais_parecido_escolhe_a_melhor_nota(self):
        base = [(ppdeep.hash(texto(2)), "Outra"), (ppdeep.hash(texto(1)), "Certa")]
        nota, nome = mais_parecido(ppdeep.hash(texto(1)), base)
        self.assertEqual((nota, nome), (100, "Certa"))


@unittest.skipUnless(ppdeep, "precisa do ppdeep")
class TesteMotorFuzzy(unittest.TestCase):
    def setUp(self):
        self.motor = MotorFuzzy()

    def test_arquivo_pequeno_nao_e_comparado(self):
        r = self.motor.analisar(Arquivo(AMOSTRAS / "teste" / "falso-virus.txt"))
        self.assertEqual(r.veredito, Veredito.LIMPO)
        self.assertIn("pequeno", r.detalhe)

    def test_amostras(self):
        esperado = {
            "teste/familia-v1.txt": Veredito.MALICIOSO,
            "teste/familia-v2.txt": Veredito.MALICIOSO,
            "teste/segredo.txt": Veredito.LIMPO,
            "teste/empacotado.exe": Veredito.LIMPO,
            "limpos/fotos.zip": Veredito.LIMPO,
        }
        for nome, veredito in esperado.items():
            r = self.motor.analisar(Arquivo(AMOSTRAS / nome))
            self.assertEqual(r.veredito, veredito, f"{nome}: {r.detalhe}")

    def test_faixas_de_veredito(self):
        pasta = Path(tempfile.mkdtemp())
        original, outro = texto(1), texto(9)
        (pasta / "base.ssdeep").write_text(f"{ppdeep.hash(original)}  Familia.X\n", encoding="utf-8")

        casos = [
            (trocar_meio(original, outro, 0.1), Veredito.MALICIOSO),  # ~97%: quase igual
            (trocar_meio(original, outro, 0.5), Veredito.SUSPEITO),   # ~72%: parente
            (outro, Veredito.LIMPO),                                  # ~0%: nada a ver
        ]
        for conteudo, esperado in casos:
            alvo = pasta / "alvo.txt"
            alvo.write_bytes(conteudo)
            r = MotorFuzzy(pasta).analisar(Arquivo(alvo))
            self.assertEqual(r.veredito, esperado, r.detalhe)

    def test_so_o_fuzzy_pega_a_v2(self):
        # A grande lição: a v2 não está na base de hash nem casa com regra YARA,
        # mas é 85% parecida com a v1, que está na base fuzzy
        arquivo = Arquivo(V2)
        self.assertEqual(MotorHash().analisar(arquivo).veredito, Veredito.LIMPO)
        if MotorYara.pronto:
            self.assertEqual(MotorYara().analisar(arquivo).veredito, Veredito.LIMPO)
        self.assertEqual(self.motor.analisar(arquivo).veredito, Veredito.MALICIOSO)


if __name__ == "__main__":
    unittest.main()
