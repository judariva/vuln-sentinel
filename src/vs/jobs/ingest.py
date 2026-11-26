"""Job de ingesta (CMP-003): una ejecución de cada conector abierto de la instancia.

    python -m vs.jobs.ingest

Por cada conector: `run_source` (fail-closed, `source_run`), guarda los hechos nuevos, pasa las
reglas y guarda evaluaciones y cambios de nivel (`vs.store.Ingestor`). Idempotente: repetirlo con
los mismos datos no guarda nada nuevo.

cvelistV5 va primero: así las señales de las demás fuentes encuentran ya su CVE. La primera
ejecución de cada fuente es su carga inicial y no alerta (ADR-0012).

Código de salida: 0 si todas las ejecuciones se guardaron (aunque alguna fuente esté en UNKNOWN,
que queda registrada como tal); 1 si alguna no se pudo guardar; 2 si la configuración no vale.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy.orm import Session

import vs.sources  # noqa: F401 - registra los conectores
from vs.api.app import api_audience
from vs.jobs.settings import NOT_INGEST, Settings, exit_with, log
from vs.sources.base import Connector, Record
from vs.sources.cvelistv5 import DEFAULT_RECORD_BASE_URL, CveListV5Connector
from vs.sources.http import Transport, get_json
from vs.sources.run import RunStatus, SourceRunResult, run_source
from vs.store import (
    ENRICHMENT_ONLY,
    CveFetcher,
    Ingestor,
    connect,
    ensure_sources,
    known_cves,
    source_state,
)

FIRST = ("cvelistv5",)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def cve_record_url(base: str, cve_id: str) -> str:
    """Ruta de un registro en cvelistV5: `cves/<año>/<n // 1000>xxx/<CVE>.json`."""
    _, year, num = cve_id.split("-")
    return f"{base}{year}/{int(num) // 1000}xxx/{cve_id}.json"


def cvelist_fetcher(conn: CveListV5Connector) -> CveFetcher:
    """Pide una CVE concreta a cvelistV5 (señal posterior a la carga inicial de una CVE que aún no
    estaba en la base de datos). Usa la misma normalización y el mismo host que el conector."""
    base = conn.config.get("record_base_url", DEFAULT_RECORD_BASE_URL)

    def fetch(cve_id: str) -> list[Record]:
        raw = get_json(conn.transport, cve_record_url(base, cve_id))
        return list(conn.normalize(raw))

    return fetch


def only_known(conn: Connector, known: set[str]) -> None:
    """Fuente de enriquecimiento: solo los registros de CVE que ya están en la base de datos."""
    original = conn.records

    def records():
        for r in original():
            if r.cve_id in known:
                yield r
            else:
                conn.count("unknown_cve_skipped")

    conn.records = records  # type: ignore[method-assign]


def select_connectors(settings: Settings, built: list[Connector]) -> list[Connector]:
    wanted = [
        c
        for c in built
        if c.name not in NOT_INGEST
        and (settings.connectors is None or c.name in settings.connectors)
    ]
    return sorted(wanted, key=lambda c: (c.name not in FIRST, built.index(c)))


def run(
    settings: Settings,
    *,
    transport: Transport | None = None,
    clock: Callable[[], datetime] = _utcnow,
) -> int:
    instance = settings.instance()
    lists = settings.lists()
    engine = connect(settings.require_db())
    built = instance.build_connectors()
    if transport is not None:
        for c in built:
            c._transport = transport
    connectors = select_connectors(settings, built)
    if not connectors:
        log("ingest_empty", detail="ningún conector de ingesta activo")
        return 0
    cvelist = next((c for c in built if isinstance(c, CveListV5Connector)), None)
    ingestor = Ingestor(
        engine,
        instance,
        api_audience(instance),
        lists,
        fetch_cve=cvelist_fetcher(cvelist) if cvelist is not None else None,
    )
    with Session(engine) as session, session.begin():
        ensure_sources(session, built)

    failures = 0
    for conn in connectors:
        with Session(engine) as session:
            state = source_state(session, conn.name)
            known = known_cves(session) if conn.name in ENRICHMENT_ONLY else None
        if known is not None:
            only_known(conn, known)
        result = run_source(
            conn,
            since=state.cursor,
            baseline_completed_at=state.baseline_completed_at,
            clock=clock,
        )
        try:
            run_id, stats = ingestor.save(result)
        except Exception as exc:
            failures += 1
            error = f"guardar: {type(exc).__name__}: {exc}"[:500]
            failed = SourceRunResult(
                source=result.source,
                started_at=result.started_at,
                finished_at=clock(),
                status=RunStatus.UNKNOWN,
                error=error,
                data_as_of=result.data_as_of,
                baseline=result.baseline,
            )
            run_id, stats = ingestor.save(failed)
            result = failed
        log(
            "source_run",
            source=result.source,
            run_id=run_id,
            status=result.status.value,
            baseline=result.baseline,
            items_seen=result.items_seen,
            data_as_of=result.data_as_of,
            error=result.error,
            connector_stats=result.stats,
            **stats.to_json(),
        )
    return 1 if failures else 0


def main(settings: Settings) -> int:
    return run(settings)


if __name__ == "__main__":
    exit_with(main)
