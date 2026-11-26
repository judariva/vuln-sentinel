"""Contenido del latido y envío sin tumbar el job.

Las columnas son las de `VsHeartbeat_CL` en `infra/bicep-legacy/platform/modules/heartbeat.bicep`,
esquema de referencia para la tabla que crea la plataforma (ADR-0025; un test
comprueba que coinciden). `UnknownSources` lleva cada fuente en UNKNOWN y **desde cuándo**, para la
regla «más de 2 h»; `AiCostUsdToday`, el coste de IA acumulado del día, para la regla «80 % del
tope» (1,5 USD/día, PLAN §7).
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from vs.feed.osv import ts
from vs.heartbeat.client import HeartbeatClient, HeartbeatError
from vs.sources.health import SourceHealth

log = logging.getLogger(__name__)

JOBS = ("ingest", "investigate", "publish", "daily")
MAX_VERSION_LEN = 128


class Outcome(StrEnum):
    OK = "ok"
    PARTIAL = "partial"  # el job terminó, pero alguna fuente o candidato quedó sin resolver
    FAILED = "failed"


@dataclass(frozen=True)
class Heartbeat:
    job: str
    run_id: str
    outcome: Outcome
    started_at: datetime
    finished_at: datetime
    unknown_sources: tuple[SourceHealth, ...] = ()
    ai_cost_usd_today: float = 0.0
    version: str = "dev"

    def __post_init__(self) -> None:
        if self.job not in JOBS:
            raise ValueError(f"job no válido: {self.job!r}")
        if not self.run_id:
            raise ValueError("run_id vacío")
        if self.started_at.tzinfo is None or self.finished_at.tzinfo is None:
            raise ValueError("marcas de tiempo sin zona horaria")
        if self.finished_at < self.started_at:
            raise ValueError("finished_at anterior a started_at")
        if not math.isfinite(self.ai_cost_usd_today) or self.ai_cost_usd_today < 0:
            raise ValueError("coste de IA no válido")
        if any(not s.unknown for s in self.unknown_sources):
            raise ValueError("unknown_sources solo admite fuentes en UNKNOWN")
        if not self.version or len(self.version) > MAX_VERSION_LEN:
            raise ValueError("versión vacía o demasiado larga")

    @classmethod
    def from_health(cls, health: Iterable[SourceHealth], **kwargs: Any) -> Heartbeat:
        """Latido con las fuentes en UNKNOWN sacadas de la salud de todas las fuentes."""
        return cls(unknown_sources=tuple(h for h in health if h.unknown), **kwargs)

    def to_row(self) -> dict[str, Any]:
        """Fila de `VsHeartbeat_CL` (columnas de la DCR)."""
        duration = self.finished_at - self.started_at
        return {
            "TimeGenerated": ts(self.finished_at),
            "Job": self.job,
            "RunId": self.run_id,
            "Outcome": self.outcome.value,
            "StartedAt": ts(self.started_at),
            "DurationMs": int(duration.total_seconds() * 1000),
            "UnknownSources": [
                {"source": s.source, "since": ts(s.since)}
                for s in sorted(self.unknown_sources, key=lambda s: s.source)
            ],
            "AiCostUsdToday": round(self.ai_cost_usd_today, 6),
            "Version": self.version,
        }


def emit(client: HeartbeatClient, beat: Heartbeat) -> bool:
    """Envía el latido. Un fallo se registra y devuelve False: **no** tumba el job.

    No hace falta más: si el latido no llega, la regla «sin latido en 20 min» de Sentinel salta, y
    el vigilante externo no depende de él.
    """
    try:
        client.send([beat.to_row()])
    except HeartbeatError as exc:
        log.warning("latido de %s no enviado: %s", beat.job, exc)
        return False
    return True
