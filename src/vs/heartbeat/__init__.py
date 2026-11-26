"""Latido de los jobs hacia Sentinel por la Logs Ingestion API (PLAN §11, G-7, CMP-033).

Cada job, al terminar, envía una fila a la tabla `VsHeartbeat_CL`: job, resultado, fuentes en
UNKNOWN y coste de IA del día. Las tres reglas de Sentinel (sin latido de `ingest` en 20 min, una
fuente en UNKNOWN más de 2 h, coste de IA por encima del 80 % del tope) leen esa tabla; crearlas es
un requisito de plataforma (G-7), no de este código.
"""

from vs.heartbeat.beat import JOBS, Heartbeat, Outcome, emit
from vs.heartbeat.client import (
    FakeHeartbeatClient,
    HeartbeatClient,
    HeartbeatError,
    LogsIngestionClient,
    ManagedIdentityTokenProvider,
)

__all__ = [
    "JOBS",
    "FakeHeartbeatClient",
    "Heartbeat",
    "HeartbeatClient",
    "HeartbeatError",
    "LogsIngestionClient",
    "ManagedIdentityTokenProvider",
    "Outcome",
    "emit",
]
