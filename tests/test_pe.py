"""Testes do motor de estrutura PE (Aula 4).

A lógica de pontuação é testada DIRETO nas funções (avaliar_imports,
avaliar_secoes), sem precisar de nenhum executável de verdade. Os poucos testes
que abrem um .exe usam os programas legítimos do próprio Windows.

Rodar: python -m unittest discover tests
"""

import unittest
from pathlib import Path

from superav.core.motor import Arquivo, Veredito
from superav.motores.pe import (
    AnalisePE,
    MotorPE,
    avaliar_imports,
    avaliar_secoes,
    classificar,
    pefile,
)

SYSTEM32 = Path(r"C:\Windows\System32")


def pontuar_imports(nomes):
    a = AnalisePE()
    avaliar_imports(set(nomes), a)
    return a


def pontuar_secoes(secoes):
    a = AnalisePE()
    avaliar_secoes(secoes, a)
    return a


class TesteImports(unittest.TestCase):
    def test_injecao_de_codigo_pontua_alto(self):
        a = pontuar_imports({"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"})
        self.assertGreaterEqual(a.pontos, 4)
        self.assertIn("injeção de código", a.sinais[0].texto)

    def test_uma_funcao_de_memoria_e_sinal_fraco(self):
        self.assertEqual(pontuar_imports({"WriteProcessMemory"}).pontos, 1)

    def test_keylogger(self):
        self.assertIn("teclado", pontuar_imports({"SetWindowsHookExA"}).sinais[0].texto)

    def test_imports_escondidos(self):
        poucos = {"LoadLibraryA", "LoadLibraryW", "GetProcAddress", "ExitProcess"}
        self.assertGreaterEqual(pontuar_imports(poucos).pontos, 2)

    def test_carga_dinamica_num_programa_grande_nao_conta(self):
        # Programas normais também usam LoadLibrary; só é suspeito se forem quase
        # as ÚNICAS funções. Aqui há muitas outras, então não pontua por isso.
        nomes = {"LoadLibraryA", "LoadLibraryW", "GetProcAddress"} | {f"Func{i}" for i in range(30)}
        self.assertEqual(pontuar_imports(nomes).pontos, 0)

    def test_programa_comum_nao_pontua(self):
        self.assertEqual(pontuar_imports({"CreateFileW", "ReadFile", "printf", "malloc"}).pontos, 0)


class TesteSecoes(unittest.TestCase):
    def test_secoes_normais(self):
        normais = [(".text", 6.2), (".rdata", 5.5), (".data", 1.6), (".rsrc", 6.9)]
        self.assertEqual(pontuar_secoes(normais).pontos, 0)

    def test_secao_de_packer(self):
        a = pontuar_secoes([("UPX0", 0.0), ("UPX1", 7.9)])
        self.assertIn("packer", a.sinais[0].texto)
        self.assertGreaterEqual(a.pontos, 3)

    def test_nome_de_secao_fora_do_padrao(self):
        self.assertEqual(pontuar_secoes([(".text", 6.0), (".evil", 5.0)]).pontos, 1)

    def test_codigo_com_entropia_alta(self):
        self.assertGreaterEqual(pontuar_secoes([(".text", 7.8)]).pontos, 2)


class TesteClassificar(unittest.TestCase):
    def test_faixas(self):
        def resultado(pontos):
            a = AnalisePE()
            if pontos:
                a.marcar(pontos, "teste")
            return classificar(a).veredito

        self.assertEqual(resultado(0), Veredito.LIMPO)
        self.assertEqual(resultado(2), Veredito.LIMPO)   # indício fraco
        self.assertEqual(resultado(3), Veredito.SUSPEITO)
        self.assertEqual(resultado(6), Veredito.MALICIOSO)

    def test_soma_de_sinais_vira_malicioso(self):
        a = AnalisePE()
        avaliar_imports({"VirtualAllocEx", "WriteProcessMemory"}, a)  # 4
        avaliar_secoes([("UPX0", 0.0)], a)                            # 3
        self.assertEqual(classificar(a).veredito, Veredito.MALICIOSO)


class TesteMotorEmArquivos(unittest.TestCase):
    def test_nao_executavel_passa(self):
        import tempfile
        p = Path(tempfile.mkdtemp()) / "a.txt"
        p.write_bytes(b"ola mundo, nao sou um exe")
        r = MotorPE().analisar(Arquivo(p))
        self.assertEqual(r.veredito, Veredito.LIMPO)
        self.assertIn("não é um executável", r.detalhe)

    @unittest.skipUnless(pefile and (SYSTEM32 / "notepad.exe").exists(), "precisa do Windows + pefile")
    def test_programas_legitimos_do_windows_passam(self):
        # Programas de usuário comuns, que NÃO fazem injeção de código
        for nome in ["notepad.exe", "calc.exe", "write.exe", "mspaint.exe"]:
            caminho = SYSTEM32 / nome
            if not caminho.exists():
                continue
            r = MotorPE().analisar(Arquivo(caminho))
            self.assertLess(r.veredito, Veredito.SUSPEITO, f"{nome}: {r.detalhe}")

    @unittest.skipUnless(pefile and (SYSTEM32 / "kernel32.dll").exists(), "precisa do Windows + pefile")
    def test_falso_positivo_conhecido_kernel32(self):
        # LIÇÃO: a própria kernel32.dll IMPLEMENTA as APIs de injeção, então ela
        # referencia todas elas. A heurística de imports a acusa — um falso
        # positivo clássico. Antivírus de verdade tratam isso com allowlist de
        # arquivos assinados pela Microsoft (algo para uma aula futura).
        r = MotorPE().analisar(Arquivo(SYSTEM32 / "kernel32.dll"))
        self.assertGreaterEqual(r.veredito, Veredito.SUSPEITO)


if __name__ == "__main__":
    unittest.main()
