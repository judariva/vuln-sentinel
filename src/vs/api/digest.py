"""Resumen diario (`/v1/digest/{fecha}.json`).

Sale del índice del feed completo (`all`): cada CVE publicada o cambiada ese día (UTC), con su nivel
al cierre del día, los tipos de cambio del día y el hash del registro. Lo que no alerta solo aparece
aquí (CLAUDE.md, «lo demás va solo al resumen diario»).

Solo se sirve un día cerrado: así sus bytes no cambian y la firma y el ETag son estables. Un día más
antiguo que la retención del índice da `Gone` (410) con el enlace al snapshot, como el índice.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from vs.feed.changes import ChangeEntry, ChangeLog
from vs.feed.config import FEED_SCHEMA_VERSION
from vs.feed.osv import ts
from vs.rules.levels import Level


class DayNotClosedError(ValueError):
    """El día aún no ha terminado (HTTP 404)."""


def day_bounds(day: date) -> tuple[datetime, datetime]:
    start = datetime.combine(day, time(0), tzinfo=UTC)
    return start, start + timedelta(days=1)


def build_digest(log: ChangeLog, day: date, now: datetime) -> dict[str, Any]:
    start, end = day_bounds(day)
    if end > now:
        raise DayNotClosedError(f"el día {day.isoformat()} aún no está cerrado")
    if end <= log.horizon(now):
        raise log.gone(now, "resumen")
    last: dict[str, ChangeEntry] = {}
    types: dict[str, list[str]] = {}
    for entry in log.entries():
        if start <= entry.modified < end:
            last[entry.id] = entry
            seen = types.setdefault(entry.id, [])
            if entry.type not in seen:
                seen.append(entry.type)
    counts = {lvl.label: 0 for lvl in sorted(Level, reverse=True)}
    for entry in last.values():
        counts[entry.level.label] += 1
    entries = [
        {
            "id": e.id,
            "level": e.level.label,
            "types": types[e.id],
            "modified": ts(e.modified),
            "sha256": e.sha256,
        }
        for e in sorted(last.values(), key=lambda e: (-e.level, e.id))
    ]
    return {
        "schema_version": FEED_SCHEMA_VERSION,
        "kind": "digest",
        "feed": log.feed,
        "day": day.isoformat(),
        "counts": counts,
        "entries": entries,
    }
