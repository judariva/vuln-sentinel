"""Niveles A/B/C y la regla de monotonía (PLAN.md §5.2, CTL-001).

El nivel solo sube. `nivel_final = max(determinista, IA)` y nunca por debajo del ya publicado; la
única forma de bajarlo es un acto manual registrado (`RuleEngine.manual_set_level`).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

RULES_VERSION = "1"


class Level(IntEnum):
    """Orden de los niveles: el máximo es el más urgente."""

    NONE = 0
    C = 1
    B = 2
    A = 3

    @property
    def label(self) -> str:
        """Valor del ENUM `alert_level` del modelo."""
        return "none" if self is Level.NONE else self.name

    @classmethod
    def parse(cls, value: str | Level) -> Level:
        if isinstance(value, Level):
            return value
        return cls.NONE if value == "none" else cls[value]


@dataclass(frozen=True)
class FinalLevel:
    level: Level
    # La IA propuso menos que el nivel determinista o que el publicado: se registra (ai_call).
    blocked_downgrade: bool


def final_level(
    deterministic: Level,
    ai: Level | None = None,
    published: Level = Level.NONE,
) -> FinalLevel:
    """`max(determinista, IA, publicado)`. La IA nunca baja un nivel (CTL-001)."""
    candidates = [deterministic, published]
    if ai is not None:
        candidates.append(ai)
    floor = max(deterministic, published)
    return FinalLevel(max(candidates), blocked_downgrade=ai is not None and ai < floor)
