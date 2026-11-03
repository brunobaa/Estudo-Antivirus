"""Motor: Tipo real (magic bytes) (Aula 2).

Descobre o tipo verdadeiro pelos primeiros bytes e pega extensão falsa ou dupla (foto.jpg.exe).
"""

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.registro import registrar


@registrar
class MotorTipo(Motor):
    id = "tipo"
    nome = "Tipo real (magic bytes)"
    aula = 2
    pronto = False  # vira True quando construirmos este motor na Aula 2

    def analisar(self, arquivo: Arquivo) -> Resultado:
        raise NotImplementedError("este motor é construído na Aula 2")
