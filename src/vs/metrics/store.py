"""Lectura de `metric_daily` para la API (PLAN.md §9). Solo lectura.

`job-daily` (CMP-006) ejecuta `docs/metrics/queries.sql` y guarda el resultado en `metric_daily`
(`day`, `metric`, `dimension`, `value`). La API solo lee esa tabla: la telemetría no es fuente de
métricas (CLAUDE.md).

Nombres de las métricas de transparencia (§9, ADR-0021) que la API agrega por mes:

- `cost.eur`: coste del día en EUR; `dimension` = proveedor (`azure`, `cloudflare`, `other`).
- `donations.sats`: sats recibidos el día; `dimension` = canal (`lightning`, `onchain`).
- `donations.count`: número de donaciones del día; `dimension` = canal.

Todo lo que empiece por `donations.` es dato de donaciones: con `donations.enabled = false` no sale
por ninguna ruta de la API.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from typing import Protocol

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from vs.model.schema import MetricDaily

COST_EUR = "cost.eur"
DONATIONS_PREFIX = "donations."
DONATIONS_SATS = "donations.sats"
DONATIONS_COUNT = "donations.count"
METRIC_RE = re.compile(r"[a-z0-9_]+(\.[a-z0-9_]+)*")


def is_donation_metric(metric: str) -> bool:
    return metric.startswith(DONATIONS_PREFIX)


@dataclass(frozen=True)
class MetricRow:
    day: date
    metric: str
    dimension: str
    value: float

    def to_json(self) -> dict[str, object]:
        return {
            "day": self.day.isoformat(),
            "metric": self.metric,
            "dimension": self.dimension,
            "value": self.value,
        }


class MetricsReader(Protocol):
    def rows(
        self, start: date, end: date, metrics: Iterable[str] | None = None
    ) -> list[MetricRow]: ...


def _sorted(rows: Iterable[MetricRow]) -> list[MetricRow]:
    return sorted(rows, key=lambda r: (r.day, r.metric, r.dimension))


class SqlMetricsReader:
    """Lee `metric_daily` con SQLAlchemy. Solo `SELECT`; la sesión nunca hace `flush`."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def rows(self, start: date, end: date, metrics: Iterable[str] | None = None) -> list[MetricRow]:
        stmt = select(MetricDaily).where(MetricDaily.day >= start, MetricDaily.day <= end)
        if metrics is not None:
            stmt = stmt.where(MetricDaily.metric.in_(list(metrics)))
        with Session(self.engine) as session:
            out = [
                MetricRow(r.day, r.metric, r.dimension or "", float(r.value))
                for r in session.scalars(stmt)
            ]
            session.rollback()
        return _sorted(out)


class MemoryMetricsReader:
    """Para tests y ejemplos."""

    def __init__(self, rows: Iterable[MetricRow] = ()) -> None:
        self._rows = list(rows)

    def rows(self, start: date, end: date, metrics: Iterable[str] | None = None) -> list[MetricRow]:
        wanted = None if metrics is None else set(metrics)
        return _sorted(
            r
            for r in self._rows
            if start <= r.day <= end and (wanted is None or r.metric in wanted)
        )
