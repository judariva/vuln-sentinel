"""Feed según derechos (ADR-0022, CMP-019).

Cada feed (público, por cliente) se genera filtrando los registros por lo que su audiencia puede
recibir, y el nivel se calcula **por feed**, solo con lo permitido. Si la única señal de A es
`restricted`, en el feed público esa CVE sale con el nivel que den las señales abiertas.

El nivel lo calculan las reglas reales (`vs.rules`, PLAN.md §5): `level_for_feed` para una
evaluación suelta y `engine_for_feed` para el motor con estado (carga inicial, alertas, monotonía).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime

from vs.instance import Instance
from vs.rules.engine import RuleEngine, RulesConfig, assess
from vs.rules.levels import Level
from vs.rules.lists import EMPTY_LISTS, RuleLists
from vs.sources.base import LicenseClass, Record

__all__ = [
    "PUBLIC",
    "Audience",
    "Level",
    "audience_for",
    "engine_for_feed",
    "filter_signals",
    "level_for_feed",
]


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


def level_for_feed(
    records: Iterable[Record],
    audience: Audience,
    lists: RuleLists = EMPTY_LISTS,
) -> Level:
    """Nivel determinista de una CVE en un feed: las reglas solo ven lo permitido a su audiencia.

    No decide si alerta (eso depende de la carga inicial y del nivel publicado: `RuleEngine`).
    """
    allowed = filter_signals(records, audience)
    cves = {r.cve_id for r in allowed}
    if len(cves) > 1:
        raise ValueError(f"level_for_feed evalúa una sola CVE; recibió {sorted(cves)}")
    if not cves:
        return Level.NONE
    return assess(cves.pop(), allowed, lists).level


def engine_for_feed(
    audience: Audience,
    lists: RuleLists = EMPTY_LISTS,
    config: RulesConfig | None = None,
    baselines: Mapping[str, datetime | None] | None = None,
) -> RuleEngine:
    """Motor de reglas de un feed: descarta lo que su audiencia no puede recibir."""
    return RuleEngine(audience, lists, config, baselines)
