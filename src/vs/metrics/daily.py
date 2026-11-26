"""Cálculo de `metric_daily` (CMP-006, PLAN.md §9) desde la base de datos del producto.

Ejecuta las consultas de `docs/metrics/queries.sql` para un día y guarda el resultado con los
nombres que lee el portal (`web/src/api/metrics.ts`). Recalcular un día lo sustituye entero:
es idempotente.

| Métrica | Dimensión | De dónde sale |
|---|---|---|
| `funnel.ingested`, `funnel.eligible`, `funnel.candidate` | — | `funnel_daily` |
| `funnel.alerted` | nivel | `funnel_daily` |
| `detection.p50_minutes`, `detection.p95_minutes` | nivel | `detection_time_by_level` |
| `kev_lead.p50_minutes` | — | mediana de `lead_over_kev` (solo si hay casos) |
| `misses.count` | — | `misses` |
| `ai.blocked_downgrades` | — | `ai_blocked_downgrades` |
| `changes.by_type` | tipo de cambio | `feed_change` del feed `all` |
| `cost.eur` | proveedor | `cost_daily` |
| `donations.sats`, `donations.count` | canal | `donation_received` (la API los oculta) |

Las donaciones solo salen por la API con `donations.enabled`.
"""

from __future__ import annotations

import re
import statistics
from datetime import date
from pathlib import Path

from sqlalchemy import delete, insert, text
from sqlalchemy.orm import Session

from vs.metrics.store import COST_EUR, DONATIONS_COUNT, DONATIONS_SATS, MetricRow
from vs.model.schema import MetricDaily

QUERIES = Path(__file__).resolve().parents[3] / "docs" / "metrics" / "queries.sql"
LEVELS = ("A", "B", "C")


def load_queries(path: Path = QUERIES) -> dict[str, str]:
    """Consultas por nombre (`-- name: <nombre>`), como las lee `tests/test_metrics_sql.py`."""
    body = path.read_text(encoding="utf-8")
    parts = re.split(r"^-- name: (\w+)\s*$", body, flags=re.MULTILINE)
    return {parts[i]: parts[i + 1].strip().rstrip(";") for i in range(1, len(parts), 2)}


_CHANGES = text(
    "SELECT type, count(*) FROM feed_change WHERE feed = 'all'"
    " AND modified >= CAST(:day AS date) AND modified < CAST(:day AS date) + 1 GROUP BY type"
)
_COST = text("SELECT provider, sum(amount_eur) FROM cost_daily WHERE day = :day GROUP BY provider")
_DONATIONS = text(
    "SELECT channel, sum(amount_sats), count(*) FROM donation_received"
    " WHERE received_at >= CAST(:day AS date) AND received_at < CAST(:day AS date) + 1"
    " GROUP BY channel"
)


def compute_day(session: Session, day: date, queries: dict[str, str] | None = None) -> list:
    """Filas de `metric_daily` de un día. No escribe nada."""
    q = queries or load_queries()
    p = {"day": day}
    rows: list[MetricRow] = []

    def add(metric: str, value: float | int | None, dimension: str = "") -> None:
        if value is not None:
            rows.append(MetricRow(day, metric, dimension, float(value)))

    f = session.execute(text(q["funnel_daily"]), p).mappings().one()
    add("funnel.ingested", f["ingested"])
    add("funnel.eligible", f["eligible"])
    add("funnel.candidate", f["candidates"])
    for lv in LEVELS:
        add("funnel.alerted", f[f"level_{lv.lower()}"], lv)

    for r in session.execute(text(q["detection_time_by_level"]), p).mappings():
        add("detection.p50_minutes", _minutes(r["p50_seconds"]), r["level"])
        add("detection.p95_minutes", _minutes(r["p95_seconds"]), r["level"])

    leads = [
        float(r["lead_hours"]) for r in session.execute(text(q["lead_over_kev"]), p).mappings()
    ]
    if leads:
        add("kev_lead.p50_minutes", statistics.median(leads) * 60)

    add("misses.count", len(session.execute(text(q["misses"]), p).all()))
    add("ai.blocked_downgrades", session.execute(text(q["ai_blocked_downgrades"]), p).scalar_one())

    for kind, n in session.execute(_CHANGES, p):
        add("changes.by_type", n, kind)
    for provider, amount in session.execute(_COST, p):
        add(COST_EUR, amount, provider)
    for channel, sats, n in session.execute(_DONATIONS, p):
        add(DONATIONS_SATS, sats, channel)
        add(DONATIONS_COUNT, n, channel)
    return rows


def _minutes(seconds) -> float | None:
    return None if seconds is None else float(seconds) / 60


def save_day(session: Session, day: date, rows: list[MetricRow]) -> int:
    """Sustituye las métricas del día por las calculadas."""
    session.execute(delete(MetricDaily).where(MetricDaily.day == day))
    if rows:
        session.execute(
            insert(MetricDaily),
            [
                {"day": r.day, "metric": r.metric, "dimension": r.dimension, "value": r.value}
                for r in rows
            ],
        )
    return len(rows)
