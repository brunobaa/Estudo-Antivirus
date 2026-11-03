"""Motor: Reputação online (Aula 11).

Consulta o hash do arquivo em serviços de reputação (VirusTotal).
"""

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.registro import registrar


@registrar
class MotorReputacao(Motor):
    id = "reputacao"
    nome = "Reputação online"
    aula = 11
    pronto = False  # vira True quando construirmos este motor na Aula 11

    def analisar(self, arquivo: Arquivo) -> Resultado:
        raise NotImplementedError("este motor é construído na Aula 11")
