"""Motor: Estrutura PE (.exe) (Aula 4).

Abre executáveis do Windows e procura imports e seções suspeitas.
"""

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.registro import registrar


@registrar
class MotorPE(Motor):
    id = "pe"
    nome = "Estrutura PE (.exe)"
    aula = 4
    pronto = False  # vira True quando construirmos este motor na Aula 4

    def analisar(self, arquivo: Arquivo) -> Resultado:
        raise NotImplementedError("este motor é construído na Aula 4")
