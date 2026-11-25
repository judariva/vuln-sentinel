"""Feed según derechos (ADR-0022, esbozo).

Cada feed (público, por cliente) se genera filtrando las señales por lo que su audiencia puede
recibir, y el nivel se calcula **por feed**, solo con las señales permitidas. Si la única señal de
A es `restricted`, en el feed público esa CVE sale con el nivel que den las señales abiertas.

`toy_level` es un nivel de juguete para probar el filtro. Lo sustituyen las reglas de T4
(`PLAN.md` §5).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import IntEnum

from vs.instance import Instance
from vs.sources.base import LicenseClass, Record


class Level(IntEnum):
    """Orden de los niveles: el máximo es el más urgente."""

    NONE = 0
    C = 1
    B = 2
    A = 3


@dataclass(frozen=True)
class Audience:
    """Lo que puede recibir un feed: clases de licencia y licencias concretas."""

    name: str
    license_classes: frozenset[LicenseClass]
    licenses: frozenset[str] = frozenset()

    def allows(self, rec: Record) -> bool:
        if rec.license_class not in self.license_classes:
            return False
        return rec.license_class is LicenseClass.OPEN or rec.licensee in self.licenses


PUBLIC = Audience("public", frozenset({LicenseClass.OPEN}))


def audience_for(instance: Instance, name: str, licenses: Iterable[str] = ()) -> Audience:
    """Audiencia de un feed de la instancia. No puede recibir más de lo que la instancia admite."""
    wanted = frozenset(licenses)
    extra = wanted - instance.licenses
    if extra:
        raise ValueError(f"la audiencia '{name}' pide licencias que la instancia no tiene: {extra}")
    classes = frozenset({LicenseClass.OPEN})
    if wanted:
        classes |= {LicenseClass.RESTRICTED}
    return Audience(name, classes, wanted)


def filter_signals(signals: Iterable[Record], audience: Audience) -> list[Record]:
    return [s for s in signals if audience.allows(s)]


_A_KINDS = frozenset({"kev_cisa", "kev_vulncheck", "vendor_exploited"})


def toy_level(signals: Iterable[Record]) -> Level:
    """Nivel de juguete: A si hay una señal de explotación; si no, NONE. Lo sustituye T4."""
    for s in signals:
        if s.kind in _A_KINDS:
            return Level.A
        if s.kind == "ssvc" and s.value.get("exploitation") == "active":
            return Level.A
    return Level.NONE


def level_for_feed(
    signals: Iterable[Record],
    audience: Audience,
    rules: Callable[[Iterable[Record]], Level] = toy_level,
) -> Level:
    """Nivel de una CVE en un feed: las reglas solo ven las señales permitidas a su audiencia."""
    return rules(filter_signals(signals, audience))
