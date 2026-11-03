"""Motor: Scripts e macros (Aula 7).

Analisa scripts (PowerShell, JS, VBS) e macros em busca de ofuscação e comandos perigosos.
"""

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.registro import registrar


@registrar
class MotorScripts(Motor):
    id = "scripts"
    nome = "Scripts e macros"
    aula = 7
    pronto = False  # vira True quando construirmos este motor na Aula 7

    def analisar(self, arquivo: Arquivo) -> Resultado:
        raise NotImplementedError("este motor é construído na Aula 7")
