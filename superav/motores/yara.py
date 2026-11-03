"""Motor: Regras YARA (Aula 5).

Procura padrões de bytes e strings usando regras YARA.
"""

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.registro import registrar


@registrar
class MotorYara(Motor):
    id = "yara"
    nome = "Regras YARA"
    aula = 5
    pronto = False  # vira True quando construirmos este motor na Aula 5

    def analisar(self, arquivo: Arquivo) -> Resultado:
        raise NotImplementedError("este motor é construído na Aula 5")
