"""Motor: Hash por semelhança (Aula 6).

Fuzzy hashing: detecta arquivos PARECIDOS com malware conhecido, não só idênticos.
"""

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.registro import registrar


@registrar
class MotorFuzzy(Motor):
    id = "fuzzy"
    nome = "Hash por semelhança"
    aula = 6
    pronto = False  # vira True quando construirmos este motor na Aula 6

    def analisar(self, arquivo: Arquivo) -> Resultado:
        raise NotImplementedError("este motor é construído na Aula 6")
