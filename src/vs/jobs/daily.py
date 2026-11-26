"""Job diario (CMP-006): calcula `metric_daily`.

    python -m vs.jobs.daily [AAAA-MM-DD ...]

Sin argumentos recalcula ayer (el día que se cierra) y hoy (parcial, para que el portal no espere
al día siguiente). Es idempotente: se puede ejecutar cada hora.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from datetime import UTC, date, datetime, timedelta

from sqlalchemy.orm import Session

from vs.jobs.settings import Settings, SettingsError, exit_with, log
from vs.metrics.daily import compute_day, load_queries, save_day
from vs.store import connect


def _utcnow() -> datetime:
    return datetime.now(UTC)


def days_from_args(args: Sequence[str], today: date) -> list[date]:
    if not args:
        return [today - timedelta(days=1), today]
    try:
        return [date.fromisoformat(a) for a in args]
    except ValueError as exc:
        raise SettingsError(f"fecha no válida: {exc}") from exc


def run(
    settings: Settings,
    args: Sequence[str] = (),
    *,
    clock: Callable[[], datetime] = _utcnow,
) -> int:
    days = days_from_args(args, clock().date())
    engine = connect(settings.require_db())
    queries = load_queries()
    for day in days:
        with Session(engine) as session, session.begin():
            rows = compute_day(session, day, queries)
            save_day(session, day, rows)
        log(
            "metric_daily",
            day=day.isoformat(),
            rows=len(rows),
            values={f"{r.metric}{':' + r.dimension if r.dimension else ''}": r.value for r in rows},
        )
    return 0


def main(settings: Settings) -> int:
    return run(settings, sys.argv[1:])


if __name__ == "__main__":
    exit_with(main)
