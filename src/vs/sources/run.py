"""Ejecución de un conector: una fila de `source_run` por ejecución y fail-closed (PLAN §4).

Reglas:
- Cualquier fallo (timeout, HTTP 5xx, JSON roto, lectura incompleta, error del conector) da
  `unknown` y **ningún registro**: no se guarda media ejecución como si fuera completa.
- Si la fuente no dice de cuándo es su dato, o es más viejo que el umbral, también `unknown`.
  Nunca se publica «sin novedades» por una fuente caída o parada.
- Carga inicial (ADR-0012): si la fuente aún no tiene `baseline_completed_at`, todos los registros
  salen con `baseline = true`, y solo una ejecución `ok` la da por terminada.
- `observed_at` lo sella aquí el ejecutor, con la hora de la ejecución.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from vs.sources.base import Connector, Record
from vs.sources.http import SourceStale

MAX_ERROR_LEN = 500


class RunStatus(StrEnum):
    """Valores del ENUM `run_status` del modelo."""

    OK = "ok"
    PARTIAL = "partial"  # reservado; ningún conector de T3 lo usa: lo incompleto es UNKNOWN
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SourceRunResult:
    source: str
    started_at: datetime
    finished_at: datetime
    status: RunStatus
    items_seen: int = 0
    items_new: int = 0
    error: str | None = None
    last_item_published_at: datetime | None = None
    data_as_of: datetime | None = None
    baseline: bool = False
    # True si esta ejecución cierra la carga inicial: quien guarda fija
    # `source.baseline_completed_at = finished_at`.
    baseline_completed: bool = False
    records: tuple[Record, ...] = ()
    stats: dict[str, int] = field(default_factory=dict)

    def to_row(self) -> dict[str, Any]:
        """Fila de `source_run`."""
        return {
            "source": self.source,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status.value,
            "items_seen": self.items_seen,
            "items_new": self.items_new,
            "error": self.error,
            "last_item_published_at": self.last_item_published_at,
        }


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _error_text(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}"
    return text[:MAX_ERROR_LEN]


def run_source(
    connector: Connector,
    *,
    since: datetime | None = None,
    baseline_completed_at: datetime | None = None,
    seen: Callable[[Record], bool] | None = None,
    clock: Callable[[], datetime] = _utcnow,
) -> SourceRunResult:
    """Ejecuta el conector una vez y devuelve la fila de `source_run` con sus registros.

    `since` es el cursor (lo último leído en una ejecución `ok`); `seen` dice si un registro ya
    estaba guardado, para contar `items_new`.
    """
    started = clock()
    baseline = baseline_completed_at is None
    connector.since = since
    connector.data_as_of = None
    connector.stats = {}

    def failed(exc: BaseException) -> SourceRunResult:
        return SourceRunResult(
            source=connector.name,
            started_at=started,
            finished_at=clock(),
            status=RunStatus.UNKNOWN,
            error=_error_text(exc),
            data_as_of=connector.data_as_of,
            baseline=baseline,
            stats=dict(connector.stats),
        )

    try:
        raw_records = list(connector.records())
        as_of = connector.data_as_of
        if as_of is None:
            raise SourceStale("la fuente no indica la fecha de su dato")
        threshold = connector.threshold()
        if threshold is not None and started - as_of > threshold:
            raise SourceStale(f"dato del {as_of.isoformat()}, más viejo que el umbral {threshold}")
    except Exception as exc:  # fail-closed: cualquier fallo es UNKNOWN
        return failed(exc)

    records = tuple(replace(r, observed_at=started, baseline=baseline) for r in raw_records)
    published = [r.source_published_at for r in records if r.source_published_at is not None]
    is_seen = seen or (lambda _r: False)
    return SourceRunResult(
        source=connector.name,
        started_at=started,
        finished_at=clock(),
        status=RunStatus.OK,
        items_seen=len(records),
        items_new=sum(1 for r in records if not is_seen(r)),
        last_item_published_at=max(published) if published else None,
        data_as_of=as_of,
        baseline=baseline,
        baseline_completed=baseline,
        records=records,
        stats=dict(connector.stats),
    )
