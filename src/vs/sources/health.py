"""Salud de cada fuente a partir de sus ejecuciones (`source_run`), para el latido y el feed.

De cada fuente interesa su estado actual (el de la última ejecución) y **desde cuándo** está así:
la regla «una fuente en UNKNOWN más de 2 h» (PLAN §11) mide la racha, no una ejecución suelta.

- `since` es el inicio de la primera ejecución de la racha final con el mismo estado.
- `last_ok_at` es el final de la última ejecución `ok` (None si nunca la hubo).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from vs.feed.osv import ts
from vs.sources.run import RunStatus, SourceRunResult


@dataclass(frozen=True)
class SourceHealth:
    source: str
    status: RunStatus
    since: datetime
    last_ok_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.source:
            raise ValueError("fuente sin nombre")
        if self.since.tzinfo is None:
            raise ValueError("since sin zona horaria")

    @property
    def unknown(self) -> bool:
        return self.status is RunStatus.UNKNOWN

    def to_json(self) -> dict[str, Any]:
        """Entrada de `sources` en el índice «head» del feed (`schema/feed-1.0.0.json`)."""
        return {"name": self.source, "status": self.status.value, "since": ts(self.since)}


def source_health(runs: Iterable[SourceRunResult]) -> list[SourceHealth]:
    """Estado actual de cada fuente, ordenado por nombre."""
    by_source: dict[str, list[SourceRunResult]] = {}
    for run in runs:
        by_source.setdefault(run.source, []).append(run)
    out = []
    for source in sorted(by_source):
        history = sorted(by_source[source], key=lambda r: (r.started_at, r.finished_at))
        last = history[-1]
        since = last.started_at
        for run in reversed(history):
            if run.status is not last.status:
                break
            since = run.started_at
        oks = [r.finished_at for r in history if r.status is RunStatus.OK]
        out.append(SourceHealth(source, last.status, since, max(oks) if oks else None))
    return out


def unknown_sources(health: Iterable[SourceHealth]) -> list[SourceHealth]:
    return [h for h in health if h.unknown]


__all__ = ["SourceHealth", "source_health", "unknown_sources"]
