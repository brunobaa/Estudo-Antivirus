"""Testes do motor de scripts e macros (Aula 7).

A pontuação é testada com trechos de texto NEUTROS que só mencionam os termos;
nenhum teste contém um script malicioso de verdade.

Rodar: python -m unittest discover tests
"""

import base64
import random
import tempfile
import unittest
from pathlib import Path

from superav.core.motor import Arquivo, Veredito
from superav.motores.scripts import MotorScripts, analisar_texto, decodificar, e_script

AMOSTRAS = Path(__file__).resolve().parent.parent / "amostras"


def pontos(texto):
    return analisar_texto(texto).pontos


class TesteIndicadores(unittest.TestCase):
    def test_script_comum_nao_pontua(self):
        self.assertEqual(pontos('Write-Host "Ola"\nGet-Date\n$x = 1 + 2\n'), 0)

    def test_maiusculas_nao_importam(self):
        self.assertEqual(pontos("menciona INVOKE-EXPRESSION"), pontos("menciona invoke-expression"))

    def test_cada_termo_conta_uma_vez(self):
        self.assertEqual(pontos("eval( eval( eval( eval("), 2)

    def test_palavra_curta_so_como_palavra_inteira(self):
        self.assertEqual(pontos("o texto cita iex sozinho"), 2)
        self.assertEqual(pontos("abre o iexplore.exe"), 0)  # "iex" dentro de iexplore não conta

    def test_combinacao_download_e_execucao_vale_mais(self):
        separados = pontos("downloadstring") + pontos("invoke-expression")
        juntos = pontos("palavras citadas: downloadstring invoke-expression")
        self.assertEqual(juntos, separados + 2)


class TesteOfuscacao(unittest.TestCase):
    def test_bloco_base64_longo(self):
        bloco = base64.b64encode(random.Random(1).randbytes(300)).decode()
        self.assertEqual(pontos(f'var x = "{bloco}";'), 2)
        self.assertEqual(pontos('var x = "b2xh";'), 0)  # Base64 curto é normal

    def test_linha_gigante(self):
        self.assertEqual(pontos("a = 1; " * 200), 1)

    def test_texto_picotado(self):
        picotado = "var s = " + ' + '.join(['"a"'] * 25) + ";"
        self.assertGreaterEqual(pontos(picotado), 2)

    def test_caracteres_por_codigo(self):
        self.assertEqual(pontos("x = " + " + ".join(["[char]65"] * 12)), 2)

    def test_crases_no_meio_das_palavras(self):
        self.assertEqual(pontos("W`r`i`t`e-H`o`s`t oi"), 2)
        self.assertEqual(pontos("um `acento` comum"), 0)

    def test_circunflexos_no_meio_das_palavras(self):
        self.assertEqual(pontos("e^c^h^o o^i^ m^u^n^d^o"), 2)


class TesteDecodificar(unittest.TestCase):
    def test_utf16_com_bom(self):
        self.assertIn("Write-Host", decodificar("Write-Host oi".encode("utf-16")))

    def test_utf16_sem_bom(self):
        self.assertIn("Write-Host", decodificar("Write-Host oi".encode("utf-16-le")))

    def test_utf8(self):
        self.assertEqual(decodificar("olá".encode()), "olá")

    def test_indicador_em_utf16_tambem_e_achado(self):
        # Sem decodificar, "invoke" em UTF-16 vira i.n.v.o.k.e e não seria achado
        texto = decodificar("menciona invoke-expression".encode("utf-16"))
        self.assertEqual(pontos(texto), 2)


class TesteMotorScripts(unittest.TestCase):
    def test_extensoes(self):
        for nome in ["a.ps1", "a.JS", "a.vbs", "a.bat", "a.cmd", "a.hta", "foto.jpg.js"]:
            self.assertTrue(e_script(nome), nome)
        for nome in ["a.txt", "a.exe", "a.py", "LEIAME"]:
            self.assertFalse(e_script(nome), nome)

    def test_nao_script_e_ignorado(self):
        pasta = Path(tempfile.mkdtemp())
        p = pasta / "texto.txt"
        p.write_bytes(b"este texto cita eval( e fromcharcode e invoke-expression")
        r = MotorScripts().analisar(Arquivo(p))
        self.assertEqual(r.veredito, Veredito.LIMPO)
        self.assertIn("não é um script", r.detalhe)

    def test_amostras(self):
        esperado = {
            "limpos/ola.ps1": Veredito.LIMPO,
            "limpos/backup.bat": Veredito.LIMPO,
            "teste/ofuscado.js": Veredito.MALICIOSO,
        }
        for nome, veredito in esperado.items():
            r = MotorScripts().analisar(Arquivo(AMOSTRAS / nome))
            self.assertEqual(r.veredito, veredito, f"{nome}: {r.detalhe}")


if __name__ == "__main__":
    unittest.main()
