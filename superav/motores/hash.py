"""Motor: Assinatura (hash) (Aula 1).

Compara o SHA-256 do arquivo com uma base de assinaturas de malware conhecido.
"""

from superav.core.motor import Arquivo, Motor, Resultado
from superav.core.registro import registrar


@registrar
class MotorHash(Motor):
    id = "hash"
    nome = "Assinatura (hash)"
    aula = 1
    pronto = False  # vira True quando construirmos este motor na Aula 1

    def analisar(self, arquivo: Arquivo) -> Resultado:
        raise NotImplementedError("este motor é construído na Aula 1")
