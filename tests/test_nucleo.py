"""Testes do núcleo, usando motores "de mentira" para não depender de nenhuma aula.

Rodar: python -m unittest discover tests
"""

import tempfile
import unittest
from pathlib import Path

from superav.core.motor import Arquivo, Motor, Resultado, Veredito
from superav.core.registro import carregar_motores
from superav.core.scanner import escanear, escanear_arquivo, listar_arquivos


class SempreLimpo(Motor):
    id, nome = "limpo", "Sempre limpo"

    def analisar(self, arquivo):
        return Resultado.limpo()


class AchaPalavraVirus(Motor):
    id, nome = "palavra", "Acha a palavra VIRUS"

    def analisar(self, arquivo):
        if b"VIRUS" in arquivo.dados:
            return Resultado.malicioso("achei VIRUS")
        return Resultado.limpo()


class Quebrado(Motor):
    id, nome = "quebrado", "Motor com bug"

    def analisar(self, arquivo):
        raise RuntimeError("bug!")


class NaoPronto(Motor):
    id, nome, aula, pronto = "futuro", "Motor do futuro", 99, False

    def analisar(self, arquivo):
        raise AssertionError("não deveria ser chamado")


class TesteNucleo(unittest.TestCase):
    def setUp(self):
        self.pasta = Path(tempfile.mkdtemp())
        (self.pasta / "bom.txt").write_bytes(b"ola mundo")
        (self.pasta / "sub").mkdir()
        (self.pasta / "sub" / "mau.txt").write_bytes(b"isto e um VIRUS")

    def test_pior_veredito_vence(self):
        rel = escanear_arquivo(self.pasta / "sub" / "mau.txt", [SempreLimpo(), AchaPalavraVirus()])
        self.assertEqual(rel.veredito_final, Veredito.MALICIOSO)

    def test_arquivo_limpo(self):
        rel = escanear_arquivo(self.pasta / "bom.txt", [SempreLimpo(), AchaPalavraVirus()])
        self.assertEqual(rel.veredito_final, Veredito.LIMPO)

    def test_motor_quebrado_nao_derruba_os_outros(self):
        rel = escanear_arquivo(self.pasta / "sub" / "mau.txt", [Quebrado(), AchaPalavraVirus()])
        vereditos = [r.veredito for _, r in rel.resultados]
        self.assertEqual(vereditos, [Veredito.ERRO, Veredito.MALICIOSO])

    def test_motor_nao_pronto_fica_pendente(self):
        rel = escanear_arquivo(self.pasta / "bom.txt", [NaoPronto()])
        self.assertEqual(rel.veredito_final, Veredito.PENDENTE)
        self.assertIn("Aula 99", rel.resultados[0][1].detalhe)

    def test_pasta_e_varrida_recursivamente(self):
        nomes = sorted(p.name for p in listar_arquivos(self.pasta))
        self.assertEqual(nomes, ["bom.txt", "mau.txt"])
        self.assertEqual(len(list(escanear(self.pasta, [SempreLimpo()]))), 2)

    def test_conteudo_lido_uma_vez(self):
        arq = Arquivo(self.pasta / "bom.txt")
        self.assertIs(arq.dados, arq.dados)

    def test_registro_carrega_motores_em_ordem_de_aula(self):
        aulas = [m.aula for m in carregar_motores()]
        self.assertEqual(aulas, sorted(aulas))
        self.assertEqual([m.id for m in carregar_motores(["hash"])], ["hash"])
        with self.assertRaises(ValueError):
            carregar_motores(["nao_existe"])


if __name__ == "__main__":
    unittest.main()
