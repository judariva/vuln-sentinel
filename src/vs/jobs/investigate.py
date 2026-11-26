"""Job de investigación (CMP-004): el agente para los candidatos B y C (PLAN.md §7).

    python -m vs.jobs.investigate

**Apagado por defecto**: sin `VS_AGENT_ENABLED=1` sale con 0 sin hacer nada y sin coste de IA.

Encendido, lista los candidatos (alertas B y C) y falla con 3: el agente con modelo real se conecta
en la F1b (Foundry o API de Anthropic, ADR-0009), fuera de T13. Así un despliegue que lo active
por error no da la investigación por hecha.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from vs.jobs.settings import Settings, exit_with, log
from vs.model.schema import Alert
from vs.store import connect

NOT_CONNECTED = 3


def run(settings: Settings) -> int:
    if not settings.agent_enabled:
        log("investigate_disabled", detail="VS_AGENT_ENABLED no es 1: sin investigación ni coste")
        return 0
    engine = connect(settings.require_db())
    with Session(engine) as session:
        candidates = list(
            session.scalars(
                select(Alert.cve_id).where(Alert.level.in_(("B", "C"))).order_by(Alert.cve_id)
            )
        )
    log(
        "investigate_not_connected",
        candidates=candidates,
        detail="el agente con modelo real se conecta en la F1b",
    )
    return NOT_CONNECTED


def main(settings: Settings) -> int:
    return run(settings)


if __name__ == "__main__":
    exit_with(main)
