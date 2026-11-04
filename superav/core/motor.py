"""O "contrato" que todo motor de detecção precisa seguir.

Todo motor (hash, YARA, heurística...) recebe um Arquivo e devolve um
Resultado. O núcleo não sabe COMO cada motor decide; ele só sabe que todos
falam essa mesma língua. Por isso dá pra adicionar motores novos sem mexer
no resto do programa.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path


class Veredito(IntEnum):
    """Resposta de um motor. O número é a gravidade: o veredito final do
    arquivo é o MAIOR veredito entre todos os motores."""

    PENDENTE = 0   # motor ainda não implementado (chega numa aula futura)
    ERRO = 1       # o motor quebrou ao analisar; não diz nada sobre o arquivo
    LIMPO = 2      # passou
    SUSPEITO = 3   # algo estranho, mas sem certeza
    MALICIOSO = 4  # não passou: ameaça detectada


@dataclass
class Resultado:
    """O que um motor responde sobre um arquivo."""

    veredito: Veredito
    detalhe: str = ""

    @classmethod
    def limpo(cls, detalhe: str = "") -> Resultado:
        return cls(Veredito.LIMPO, detalhe)

    @classmethod
    def suspeito(cls, detalhe: str) -> Resultado:
        return cls(Veredito.SUSPEITO, detalhe)

    @classmethod
    def malicioso(cls, detalhe: str) -> Resultado:
        return cls(Veredito.MALICIOSO, detalhe)


class Arquivo:
    """Um arquivo sendo analisado.

    O conteúdo é lido do disco uma única vez, na primeira vez que algum
    motor pedir, e depois é compartilhado com todos os outros motores.
    """

    LIMITE_BYTES = 100 * 1024 * 1024  # não lê mais que 100 MB por arquivo
    BLOCO_HASH = 1024 * 1024          # o hash lê o arquivo em pedaços de 1 MB

    def __init__(self, caminho: Path):
        self.caminho = Path(caminho)
        self.tamanho = self.caminho.stat().st_size
        self._dados: bytes | None = None
        self._hashes: dict[str, str] = {}

    @property
    def dados(self) -> bytes:
        if self._dados is None:
            with open(self.caminho, "rb") as f:
                self._dados = f.read(self.LIMITE_BYTES)
        return self._dados

    def hash(self, algoritmo: str = "sha256") -> str:
        """Hash do arquivo INTEIRO (ex: "md5", "sha1", "sha256"), calculado uma vez.

        Lê em blocos, então funciona até com arquivos de vários GB sem
        carregar tudo na memória.
        """
        if algoritmo not in self._hashes:
            calculadora = hashlib.new(algoritmo)
            if self._dados is not None and len(self._dados) == self.tamanho:
                calculadora.update(self._dados)  # já está na memória
            else:
                with open(self.caminho, "rb") as f:
                    while bloco := f.read(self.BLOCO_HASH):
                        calculadora.update(bloco)
            self._hashes[algoritmo] = calculadora.hexdigest()
        return self._hashes[algoritmo]


class Motor(ABC):
    """Classe base de todo motor de detecção.

    Para criar um motor novo:
      1. crie um arquivo em superav/motores/
      2. herde de Motor e preencha id, nome e aula
      3. implemente analisar()
      4. marque a classe com @registrar
    """

    id: str = ""        # nome curto, usado na linha de comando (ex: "hash")
    nome: str = ""      # nome bonito, mostrado no relatório
    aula: int = 0       # em qual aula esse motor é construído
    pronto: bool = True  # False = ainda é só um esqueleto

    @abstractmethod
    def analisar(self, arquivo: Arquivo) -> Resultado:
        """Analisa o arquivo e devolve um Resultado."""
