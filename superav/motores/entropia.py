"""Motor: Entropia (Aula 3).

Mede o quão "aleatório" é o conteúdo: entropia alta indica arquivo compactado ou criptografado.
"""

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.registro import registrar


@registrar
class MotorEntropia(Motor):
    id = "entropia"
    nome = "Entropia"
    aula = 3
    pronto = False  # vira True quando construirmos este motor na Aula 3

    def analisar(self, arquivo: Arquivo) -> Resultado:
        raise NotImplementedError("este motor é construído na Aula 3")
