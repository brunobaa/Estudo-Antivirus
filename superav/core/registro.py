"""Registro de motores: a "lista de chamada" do antivírus.

Cada motor se inscreve aqui com o decorador @registrar. O scanner nunca
importa um motor pelo nome: ele pede a lista inteira para o registro.
"""

from __future__ import annotations

from superav.core.motor import Motor

_MOTORES: list[type[Motor]] = []


def registrar(classe: type[Motor]) -> type[Motor]:
    """Decorador: coloca a classe do motor na lista de chamada."""
    if not classe.id:
        raise ValueError(f"{classe.__name__} precisa definir um id")
    if any(m.id == classe.id for m in _MOTORES):
        raise ValueError(f"já existe um motor com id '{classe.id}'")
    _MOTORES.append(classe)
    return classe


def carregar_motores(ids: list[str] | None = None) -> list[Motor]:
    """Devolve uma instância de cada motor registrado, na ordem das aulas.

    Se `ids` for informado, devolve só esses motores.
    """
    import superav.motores  # noqa: F401  (importa e registra todos os motores)

    classes = sorted(_MOTORES, key=lambda m: m.aula)
    if ids:
        conhecidos = {m.id for m in classes}
        desconhecidos = [i for i in ids if i not in conhecidos]
        if desconhecidos:
            raise ValueError(
                f"motor(es) desconhecido(s): {', '.join(desconhecidos)}. "
                f"Disponíveis: {', '.join(sorted(conhecidos))}"
            )
        classes = [m for m in classes if m.id in ids]
    return [classe() for classe in classes]
