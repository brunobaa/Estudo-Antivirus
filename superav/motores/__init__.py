"""Pasta dos motores de detecção.

Este arquivo importa automaticamente TODO módulo .py desta pasta. Então,
para adicionar um motor novo, basta criar o arquivo aqui dentro: não
precisa mexer em mais nada.
"""

import importlib
import pkgutil

for _modulo in pkgutil.iter_modules(__path__):
    importlib.import_module(f"{__name__}.{_modulo.name}")
