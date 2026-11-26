"""Job de publicación (CMP-005): feed completo y de alertas, firmados.

    python -m vs.jobs.publish

Publica las CVE con hechos nuevos o cambios de nivel desde la última ejecución (marca de agua en
`job_state`), guarda el feed en la base de datos (`feed_record`, `feed_change`) para que la API
sirva lo mismo, y escribe los documentos y sus firmas detrás de `FeedWriter`: en local, a un
directorio (`VS_FEED_DIR`); en la F1b, a R2.

Firma con `LocalDevSigner` (clave en `.cache/` o en `VS_SIGNING_KEY`); en Azure, `KeyVaultSigner`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from sqlalchemy.orm import Session

from vs.api.app import api_audience
from vs.feed.config import FeedConfig
from vs.feed.osv import alert_id, ts
from vs.feed.publish import Document, FeedPublisher, FeedStatus
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
    set_state,
    touched_since,
)

STATE = "publish"
HEALTH_WINDOW = timedelta(days=2)


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


def _put_signed(writer: FeedWriter, pub: FeedPublisher, doc: Document) -> None:
    writer.put(doc)
    writer.put(pub.signature(doc))


def write_documents(
    writer: FeedWriter,
    pub: FeedPublisher,
    idents: Iterable[str],
    now: datetime,
    since: datetime | None,
) -> int:
    """Escribe lo que cambia en esta ejecución: registros publicados, índices, alertas y claves."""
    n = 0
    for ident in sorted(idents):
        _put_signed(writer, pub, pub.vuln(ident))
        n += 1
    for feed in ("all", "alerts"):
        _put_signed(writer, pub, pub.changes_head(feed, None, now))
        n += 1
        for doc in pub.sealed_pages(feed, now):
            hour_end = datetime.strptime(doc.path.rsplit("/", 1)[1], "%Y-%m-%dT%H.json").replace(
                tzinfo=UTC
            ) + timedelta(hours=1)
            if since is None or hour_end > since:  # solo las horas que se cierran ahora
                _put_signed(writer, pub, doc)
                n += 1
    _put_signed(writer, pub, pub.alerts_latest(now))
    writer.put(pub.keys())
    return n + 2


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
        prev_modified = state.get("modified")
        prev = (
            datetime.fromisoformat(prev_modified.replace("Z", "+00:00")) if prev_modified else None
        )
        max_run, max_hist = max_ids(session)
        touched = touched_since(
            session, int(state.get("run_id", 0)), max_run, int(state.get("history_id", 0))
        )
        pub = FeedPublisher(audience, feed_cfg, signer, lists)
        # Lo tocado (para comparar con lo publicado) y todo lo que tiene nivel (alerts/latest.json).
        pub.restore(
            load_feed_records(session, {alert_id(c) for c in touched} | alerting_ids(session)),
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
        set_state(
            session,
            STATE,
            {"run_id": max_run, "history_id": max_hist, **status.to_json()},
            now,
        )

    docs = write_documents(writer, pub, changed, now, prev)
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
        modified=ts(now),
        unknown_sources=[s.source for s in status.sources if s.unknown],
    )
    return 0


def main(settings: Settings) -> int:
    return run(settings)


if __name__ == "__main__":
    exit_with(main)
