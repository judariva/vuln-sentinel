"""Job de publicación (CMP-005): feed completo y de alertas, firmados.

    python -m vs.jobs.publish

Publica las CVE con hechos nuevos o cambios de nivel desde la última ejecución (marca de agua en
`job_state`), guarda el feed en la base de datos (`feed_record`, `feed_change`) para que la API
sirva lo mismo, y escribe los documentos y sus firmas detrás de `FeedWriter`: en local, a un
directorio (`VS_FEED_DIR`); en la F1b, a R2.

Firma con `LocalDevSigner` (clave en `.cache/` o en `VS_SIGNING_KEY`); en Azure, `KeyVaultSigner`.

ADR-0026: la API no tiene la clave. Este job firma, **en la misma transacción** en la que guarda el
feed, todo lo que la API sirve firmado y deja las firmas en `feed_signature`: los registros
cambiados (y, hasta `BACKFILL_LIMIT` por ejecución, los que aún no tienen firma de sus bytes
actuales), las páginas selladas, los resúmenes de los días cerrados, `alerts/latest.json` y el JWKS.
Así la API nunca ve un registro nuevo sin su firma. La cabeza del índice (`changes` sin hora) no
se firma: cambia con cada petición; se verifica por las páginas selladas y el sha256 de cada
registro.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Protocol

from sqlalchemy.orm import Session

from vs.api.app import api_audience
from vs.api.digest import DayNotClosedError, build_digest
from vs.feed.changes import FEEDS, Gone
from vs.feed.config import FeedConfig
from vs.feed.osv import alert_id, ts
from vs.feed.publish import (
    IMMUTABLE,
    KEYS_PATH,
    LATEST_PATH,
    Document,
    FeedPublisher,
    FeedStatus,
    StoredSignature,
)
from vs.feed.sign import Signer
from vs.jobs.settings import Settings, exit_with, log
from vs.rules.levels import Level
from vs.rules.lists import RuleLists
from vs.sources.health import source_health
from vs.store import (
    alerting_ids,
    connect,
    get_state,
    last_feed_modified,
    load_feed_entries,
    load_feed_records,
    load_history,
    load_levels,
    load_records,
    max_ids,
    recent_runs,
    save_feed,
    save_signatures,
    set_state,
    signature_hashes,
    touched_since,
    unsigned_record_ids,
)

STATE = "publish"
HEALTH_WINDOW = timedelta(days=2)
BACKFILL_LIMIT = 500
# Lo que la API no puede reconstruir igual (depende del reloj del job o de la clave): va entero.
STORED_BODIES = frozenset({LATEST_PATH, KEYS_PATH})


class FeedWriter(Protocol):
    """Dónde se escriben los documentos publicados (ruta → bytes)."""

    def put(self, doc: Document) -> None: ...


class DirWriter:
    """Escribe cada documento bajo `root`, con la ruta de la API (`/v1/...` → `root/v1/...`)."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()

    def put(self, doc: Document) -> None:
        if doc.status != 200:
            return
        target = (self.root / doc.path.lstrip("/")).resolve()
        if not target.is_relative_to(self.root):
            raise ValueError(f"ruta fuera del directorio del feed: {doc.path!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_bytes(doc.body)
        tmp.replace(target)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def closed_days(now: datetime, retention: timedelta) -> list[date]:
    """Días UTC ya cerrados dentro de la retención (los que tienen resumen inmutable)."""
    first = (now - retention).date()
    last = now.date() - timedelta(days=1)
    return [first + timedelta(days=i) for i in range((last - first).days + 1)]


def signable_documents(
    pub: FeedPublisher, idents: Iterable[str], now: datetime
) -> list[tuple[Document, datetime | None]]:
    """Lo que la API sirve firmado, con su caducidad (None = mientras exista la ruta)."""
    retention = timedelta(days=pub.config.retention_days)
    docs: list[tuple[Document, datetime | None]] = [
        (pub.vuln(i), None) for i in sorted(set(idents))
    ]
    for feed in FEEDS:
        for doc in pub.sealed_pages(feed, now):
            hour = doc.path.rsplit("/", 1)[1].removesuffix(".json")
            hour_end = datetime.strptime(hour, "%Y-%m-%dT%H").replace(tzinfo=UTC)
            docs.append((doc, hour_end + timedelta(hours=1) + retention))
    for day in closed_days(now, retention):
        try:
            digest = build_digest(pub.logs["all"], day, now)
        except (Gone, DayNotClosedError):
            continue
        doc = pub.json_document(f"/v1/digest/{day.isoformat()}.json", digest, IMMUTABLE)
        day_end = datetime.combine(day, time(0), tzinfo=UTC) + timedelta(days=1)
        docs.append((doc, day_end + retention))
    docs.append((pub.alerts_latest(now), None))
    return docs


def presign(
    pub: FeedPublisher,
    docs: Iterable[tuple[Document, datetime | None]],
    already: dict[str, str],
) -> list[tuple[Document, Document, StoredSignature, datetime | None]]:
    """Firma lo que aún no tiene firma de estos mismos bytes. Devuelve (doc, jws, fila, caduca)."""
    out = []
    for doc, expires in docs:
        if already.get(doc.path) == doc.sha256:
            continue
        jws = pub.signature(doc)
        body = doc.body if doc.path in STORED_BODIES else None
        jws_text = jws.body.decode("ascii")
        row = StoredSignature(doc.path, doc.sha256, jws_text, pub.signer.kid, body)
        out.append((doc, jws, row, expires))
    return out


def keys_row(
    pub: FeedPublisher, already: dict[str, str]
) -> tuple[Document, StoredSignature] | None:
    """El JWKS público, guardado entero (la API no tiene la clave para generarlo)."""
    doc = pub.keys()
    if already.get(doc.path) == doc.sha256:
        return None
    return doc, StoredSignature(doc.path, doc.sha256, None, pub.signer.kid, doc.body)


def write_documents(
    writer: FeedWriter,
    pub: FeedPublisher,
    signed: Iterable[tuple[Document, Document]],
    now: datetime,
) -> int:
    """Escribe lo firmado en esta ejecución, la cabeza de cada índice (firmada aquí) y el JWKS."""
    n = 0
    for doc, jws in signed:
        writer.put(doc)
        writer.put(jws)
        n += 1
    for feed in FEEDS:
        head = pub.changes_head(feed, None, now)
        writer.put(head)
        writer.put(pub.signature(head))
        n += 1
    writer.put(pub.keys())
    return n + 1


def run(
    settings: Settings,
    *,
    writer: FeedWriter | None = None,
    signer: Signer | None = None,
    clock: Callable[[], datetime] = _utcnow,
) -> int:
    instance = settings.instance()
    lists: RuleLists = settings.lists()
    feed_cfg: FeedConfig = settings.feed_config()
    signer = signer or settings.signer(feed_cfg)
    writer = writer or DirWriter(settings.feed_dir)
    engine = connect(settings.require_db())
    audience = api_audience(instance)
    now = clock()
    horizon = now - timedelta(days=feed_cfg.retention_days)

    with Session(engine) as session, session.begin():
        state = get_state(session, STATE)
        max_run, max_hist = max_ids(session)
        touched = touched_since(
            session, int(state.get("run_id", 0)), max_run, int(state.get("history_id", 0))
        )
        backfill = unsigned_record_ids(session, BACKFILL_LIMIT)
        pub = FeedPublisher(audience, feed_cfg, signer, lists)
        # Lo tocado (para comparar con lo publicado), todo lo que tiene nivel (alerts/latest.json)
        # y los registros que aún no tienen firma guardada.
        pub.restore(
            load_feed_records(
                session,
                {alert_id(c) for c in touched} | alerting_ids(session) | set(backfill),
            ),
            load_feed_entries(session, horizon),
            last_feed_modified(session),
        )
        before = {feed: len(log_) for feed, log_ in pub.logs.items()}
        records = load_records(session, touched)
        levels = load_levels(session, touched)
        history = load_history(session, touched, audience.name)
        changed: set[str] = set()
        for cve in sorted(touched):
            entry = pub.publish(cve, records[cve], levels.get(cve, Level.NONE), history[cve], now)
            if entry is not None:
                changed.add(entry.id)
        new_entries = {feed: pub.logs[feed].entries()[before[feed] :] for feed in pub.logs}
        published = {i: v for i, v in pub.published_records().items() if i in changed}
        save_feed(session, published, new_entries, horizon)
        pub.prune(now)
        status = FeedStatus(
            modified=now, sources=tuple(source_health(recent_runs(session, now - HEALTH_WINDOW)))
        )
        pub.set_status(status)
        # ADR-0026: las firmas entran en la misma transacción que el feed y que el cambio de
        # `job_state` con el que la API recarga, así que la API nunca ve bytes sin su firma.
        already = signature_hashes(session)
        signed = presign(pub, signable_documents(pub, changed | set(backfill), now), already)
        keys = keys_row(pub, already)
        rows = [(row, expires) for _doc, _jws, row, expires in signed]
        if keys is not None:
            rows.append((keys[1], None))
        save_signatures(session, rows, now)
        set_state(
            session,
            STATE,
            {"run_id": max_run, "history_id": max_hist, **status.to_json()},
            now,
        )

    docs = write_documents(writer, pub, [(d, j) for d, j, _row, _exp in signed], now)
    by_level: dict[str, int] = {}
    for _body, _sha, level in published.values():
        by_level[level.label] = by_level.get(level.label, 0) + 1
    log(
        "publish",
        touched=len(touched),
        published=len(changed),
        by_level=by_level,
        entries={f: len(e) for f, e in new_entries.items()},
        documents=docs,
        signed=len(signed),
        backfill=len(set(backfill) - changed),
        modified=ts(now),
        unknown_sources=[s.source for s in status.sources if s.unknown],
    )
    return 0


def main(settings: Settings) -> int:
    return run(settings)


if __name__ == "__main__":
    exit_with(main)
