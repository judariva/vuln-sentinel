"""Persistencia de los jobs en PostgreSQL (T13): hechos, ejecuciones, reglas y feed publicado.

Une las piezas que ya existen en memoria (`vs.sources.run`, `vs.rules.engine`,
`vs.feed.publish`) con el modelo (`vs.model.schema`). Reglas:

- **Idempotente.** Cada hecho se identifica por la huella de `Record.key()` en `fact_seen`. Volver a
  leer lo mismo no guarda nada ni evalúa nada.
- **Una ejecución, una transacción.** La fila de `source_run`, sus hechos, las evaluaciones y los
  cambios de nivel se guardan juntos o no se guarda nada.
- **Carga inicial sin alertas (ADR-0012).** Un hecho visto durante la carga inicial de su fuente
  conserva esa marca aunque su CVE llegue después a `vulnerability`: nunca alerta como nuevo.
- **CVE que aún no conocemos.** Las señales y los productos de una CVE que no está en
  `vulnerability` no se pueden guardar (clave foránea). Se anota su huella (`stored = false`) y se
  guardan cuando llega la CVE. Si una señal que puede subir el nivel llega **después** de la carga
  inicial (p. ej. una alta en KEV de una CVE antigua), se pide la CVE a cvelistV5 en ese momento,
  con un tope por ejecución.
- **Solo enriquecimiento.** EPSS solo se guarda para CVE conocidas: no crea CVE ni alerta.
- **CC-BY-SA fuera (ADR-0020).** Los registros `share_alike` no se guardan hasta la revisión legal.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Engine, delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from vs.feed.changes import ChangeEntry
from vs.feed.osv import alert_id
from vs.feed.publish import StoredSignature
from vs.instance import Instance, audit
from vs.model.migrate import create_db_engine, require_url
from vs.model.schema import (
    AffectedProduct,
    Alert,
    AlertLevelHistory,
    FactSeen,
    FeedChange,
    FeedRecord,
    FeedSignature,
    JobState,
    RuleEvaluation,
    Signal,
    Source,
    SourceRun,
    Vulnerability,
)
from vs.rules.engine import A_KINDS, AudienceLike, BatchResult, LevelChange, RuleEngine
from vs.rules.exploit import EXPLOIT_KIND
from vs.rules.levels import Level
from vs.rules.lists import EMPTY_LISTS, ProductRef, RuleLists, producto_expuesto
from vs.sources.base import Connector, Entity, LicenseClass, Record, is_cve_id
from vs.sources.run import RunStatus, SourceRunResult

DEFAULT_FRESHNESS = timedelta(hours=24)
# Fuentes que solo enriquecen: no crean CVE y su huella no se guarda si la CVE no se conoce.
ENRICHMENT_ONLY = frozenset({"epss"})
# Señales que pueden subir el nivel: si llegan tras la carga inicial para una CVE desconocida, se
# pide la CVE a cvelistV5 (`CveFetcher`).
LEVEL_KINDS = frozenset({*A_KINDS, EXPLOIT_KIND, "ssvc"})
# Campos que cambian sin que cambie el hecho: KEV repite toda su lista en cada versión del catálogo.
# Se guarda la primera versión en la que apareció la entrada.
VOLATILE_FIELDS: Mapping[str, frozenset[str]] = {"cisa_kev": frozenset({"catalog_version"})}
DEFAULT_FETCH_LIMIT = 50
MARK_BATCH = 5000
ALERT_STATUS = "active"


def connect(url: str | None = None) -> Engine:
    """Motor de SQLAlchemy desde la URL dada o la del entorno (`VS_DATABASE_URL` o Entra, ver
    `vs.model.migrate`). Nunca escribe la URL en logs."""
    return create_db_engine(require_url(url), pool_pre_ping=True)


def fact_key(record: Record) -> str:
    """Huella estable de un hecho: sha256 de `Record.key()` sin sus campos volátiles."""
    key: tuple = record.key()
    drop = VOLATILE_FIELDS.get(record.source)
    if drop:
        value = {k: v for k, v in record.value.items() if k not in drop}
        key = (*key[:4], json.dumps(value, sort_keys=True, default=str))
    raw = json.dumps(key, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _jsonable(value: Any) -> Any:
    """Lo que va a JSONB: fechas como texto RFC 3339 y nada que JSON no admita."""
    return json.loads(json.dumps(value, default=_default))


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return str(value)


# -- filas → registros ---------------------------------------------------------------------------

VULN_COLUMNS = ("cna", "cvss_vector", "cvss_source", "cwe", "vendor", "product", "withdrawn_at")
PRODUCT_COLUMNS = ("vendor", "product", "cpe", "purl", "ecosystem", "ranges", "range_source")
CVE_ORG = "https://www.cve.org/CVERecord?id="


def _lc(row: Any) -> LicenseClass:
    return LicenseClass(row.license_class)


def vuln_record(row: Vulnerability) -> Record:
    return Record(
        source=row.source,
        cve_id=row.cve_id,
        kind="vulnerability",
        license_class=_lc(row),
        licensee=row.licensee,
        entity=Entity.VULNERABILITY,
        value={c: getattr(row, c) for c in VULN_COLUMNS},
        source_published_at=row.source_published_at,
        observed_at=row.observed_at,
        baseline=row.baseline,
        url=CVE_ORG + row.cve_id,
    )


def product_record(row: AffectedProduct) -> Record:
    return Record(
        source=row.source,
        cve_id=row.cve_id,
        kind="affected_product",
        license_class=_lc(row),
        licensee=row.licensee,
        entity=Entity.AFFECTED_PRODUCT,
        value={c: getattr(row, c) for c in PRODUCT_COLUMNS},
        source_published_at=row.source_published_at,
        observed_at=row.observed_at,
    )


def signal_record(row: Signal) -> Record:
    return Record(
        source=row.source,
        cve_id=row.cve_id,
        kind=row.kind,
        license_class=_lc(row),
        licensee=row.licensee,
        entity=Entity.SIGNAL,
        value=dict(row.value or {}),
        source_published_at=row.source_published_at,
        observed_at=row.observed_at,
        baseline=row.baseline,
        url=row.url,
    )


def load_records(session: Session, cve_ids: Iterable[str]) -> dict[str, list[Record]]:
    """Todos los hechos guardados de esas CVE, en orden de observación."""
    ids = sorted(set(cve_ids))
    out: dict[str, list[Record]] = {c: [] for c in ids}
    if not ids:
        return out
    for row in session.scalars(select(Vulnerability).where(Vulnerability.cve_id.in_(ids))):
        out[row.cve_id].append(vuln_record(row))
    for row in session.scalars(
        select(AffectedProduct).where(AffectedProduct.cve_id.in_(ids)).order_by(AffectedProduct.id)
    ):
        out[row.cve_id].append(product_record(row))
    for row in session.scalars(select(Signal).where(Signal.cve_id.in_(ids)).order_by(Signal.id)):
        out[row.cve_id].append(signal_record(row))
    return out


def load_levels(session: Session, cve_ids: Iterable[str]) -> dict[str, Level]:
    ids = sorted(set(cve_ids))
    if not ids:
        return {}
    rows = session.execute(select(Alert.cve_id, Alert.level).where(Alert.cve_id.in_(ids)))
    return {cve: Level.parse(level) for cve, level in rows}


def load_history(session: Session, cve_ids: Iterable[str], feed: str) -> dict[str, list]:
    """`alert_level_history` de esas CVE como `LevelChange` del feed dado."""
    ids = sorted(set(cve_ids))
    out: dict[str, list[LevelChange]] = {c: [] for c in ids}
    if not ids:
        return out
    rows = session.execute(
        select(Alert.cve_id, AlertLevelHistory)
        .join(Alert, Alert.alert_id == AlertLevelHistory.alert_id)
        .where(Alert.cve_id.in_(ids))
        .order_by(AlertLevelHistory.at, AlertLevelHistory.id)
    )
    for cve, h in rows:
        out[cve].append(
            LevelChange(
                cve_id=cve,
                feed=feed,
                level_from=Level.parse(h.level_from),
                level_to=Level.parse(h.level_to),
                reason=tuple(h.reason or ()),
                decided_by=h.decided_by,
                at=h.at,
            )
        )
    return out


# -- fuentes y ejecuciones -----------------------------------------------------------------------


def ensure_sources(session: Session, connectors: Iterable[Connector]) -> None:
    """Una fila de `source` por conector activo (sin tocar la carga inicial ya hecha)."""
    for c in connectors:
        stmt = insert(Source).values(
            name=c.name,
            freshness_threshold=c.threshold() or DEFAULT_FRESHNESS,
            license_class=c.license_class,
            licensee=c.licensee,
        )
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=[Source.name],
                set_={"freshness_threshold": stmt.excluded.freshness_threshold},
            )
        )


@dataclass(frozen=True)
class SourceState:
    baseline_completed_at: datetime | None
    cursor: datetime | None


def source_state(session: Session, name: str) -> SourceState:
    done = session.scalar(select(Source.baseline_completed_at).where(Source.name == name))
    cursor = session.scalar(
        select(SourceRun.data_as_of)
        .where(SourceRun.source == name, SourceRun.status == RunStatus.OK.value)
        .order_by(SourceRun.id.desc())
        .limit(1)
    )
    return SourceState(done, cursor)


def baselines(session: Session) -> dict[str, datetime | None]:
    return dict(session.execute(select(Source.name, Source.baseline_completed_at)).all())


def known_cves(session: Session, cve_ids: Iterable[str] | None = None) -> set[str]:
    stmt = select(Vulnerability.cve_id)
    if cve_ids is not None:
        ids = sorted(set(cve_ids))
        if not ids:
            return set()
        stmt = stmt.where(Vulnerability.cve_id.in_(ids))
    return set(session.scalars(stmt))


def recent_runs(session: Session, since: datetime) -> list[SourceRunResult]:
    """Ejecuciones desde `since`, más la última de cada fuente aunque sea anterior."""
    last_ids = select(func.max(SourceRun.id)).group_by(SourceRun.source)
    rows = session.scalars(
        select(SourceRun)
        .where((SourceRun.started_at >= since) | SourceRun.id.in_(last_ids))
        .order_by(SourceRun.id)
    )
    return [
        SourceRunResult(
            source=r.source,
            started_at=r.started_at,
            finished_at=r.finished_at or r.started_at,
            status=RunStatus(r.status),
            items_seen=r.items_seen,
            items_new=r.items_new,
            error=r.error,
            last_item_published_at=r.last_item_published_at,
            data_as_of=r.data_as_of,
        )
        for r in rows
    ]


# -- ingesta -------------------------------------------------------------------------------------

CveFetcher = Callable[[str], list[Record]]
"""Pide una CVE a cvelistV5 y devuelve sus registros normalizados (sin sellar)."""


@dataclass
class IngestStats:
    stored: int = 0
    duplicates: int = 0
    unknown_cve: int = 0
    fetched_cves: int = 0
    fetch_failed: int = 0
    share_alike_dropped: int = 0
    evaluations: int = 0
    alerts: list[tuple[str, str, str]] = field(default_factory=list)  # (cve, de, a)

    def to_json(self) -> dict[str, Any]:
        return {
            "stored": self.stored,
            "duplicates": self.duplicates,
            "unknown_cve": self.unknown_cve,
            "fetched_cves": self.fetched_cves,
            "fetch_failed": self.fetch_failed,
            "share_alike_dropped": self.share_alike_dropped,
            "evaluations": self.evaluations,
            "alerts": [{"cve": c, "from": f, "to": t} for c, f, t in self.alerts],
        }


class Ingestor:
    """Guarda una ejecución de un conector y pasa sus hechos nuevos por las reglas."""

    def __init__(
        self,
        engine: Engine,
        instance: Instance,
        audience: AudienceLike,
        lists: RuleLists = EMPTY_LISTS,
        fetch_cve: CveFetcher | None = None,
        fetch_limit: int = DEFAULT_FETCH_LIMIT,
    ) -> None:
        self.engine = engine
        self.instance = instance
        self.audience = audience
        self.lists = lists
        self.fetch_cve = fetch_cve
        self.fetch_limit = fetch_limit

    # -- pasos --------------------------------------------------------------------------------

    def _insert_run(self, session: Session, result: SourceRunResult) -> int:
        stmt = insert(SourceRun).values(**result.to_row()).returning(SourceRun.id)
        return session.execute(stmt).scalar_one()

    def _category(self, value: Mapping[str, Any]) -> str | None:
        ref = ProductRef(
            value.get("vendor"), value.get("product"), value.get("cpe"), value.get("purl")
        )
        found = producto_expuesto([ref], self.lists)
        return found.category if found else None

    def _store(self, session: Session, r: Record) -> int | None:
        """Guarda un hecho en su tabla. Devuelve el id de la señal (o None)."""
        row = r.to_row()
        if r.entity is Entity.VULNERABILITY:
            row["cwe"] = list(row.get("cwe") or [])
            stmt = insert(Vulnerability).values(**row)
            cols = {c: stmt.excluded[c] for c in (*VULN_COLUMNS, "observed_at", "source")}
            cols["source_published_at"] = stmt.excluded.source_published_at
            cols["baseline"] = Vulnerability.baseline & stmt.excluded.baseline
            session.execute(stmt.on_conflict_do_update(index_elements=["cve_id"], set_=cols))
            return None
        if r.entity is Entity.AFFECTED_PRODUCT:
            row["ranges"] = _jsonable(row.get("ranges") or [])
            row.setdefault("range_source", r.source)
            row["range_source"] = row["range_source"] or r.source
            row["category"] = self._category(row)
            session.execute(insert(AffectedProduct).values(**row))
            return None
        row["value"] = _jsonable(row["value"])
        return session.execute(insert(Signal).values(**row).returning(Signal.id)).scalar_one()

    def _seen(self, session: Session, source: str, keys: Iterable[str]) -> dict[str, FactSeen]:
        ks = list(keys)
        if not ks:
            return {}
        rows = session.scalars(
            select(FactSeen).where(FactSeen.source == source, FactSeen.fact_key.in_(ks))
        )
        return {r.fact_key: r for r in rows}

    @staticmethod
    def _mark(marks: list, source: str, key: str, r: Record, run_id: int, stored: bool) -> None:
        marks.append(
            {
                "source": source,
                "fact_key": key,
                "cve_id": r.cve_id,
                "run_id": run_id,
                "baseline": r.baseline,
                "first_observed_at": r.observed_at,
                "stored": stored,
            }
        )

    @staticmethod
    def _flush_marks(session: Session, marks: list) -> None:
        """Huella de los hechos, en lotes. Si ya estaba, solo cambian `stored` y `run_id`."""
        stmt = insert(FactSeen)
        stmt = stmt.on_conflict_do_update(
            index_elements=["source", "fact_key"],
            set_={"stored": stmt.excluded.stored, "run_id": stmt.excluded.run_id},
        )
        for i in range(0, len(marks), MARK_BATCH):
            session.execute(stmt, marks[i : i + MARK_BATCH])
        marks.clear()

    def _fetch(self, cve_id: str, at: datetime, stats: IngestStats) -> list[Record]:
        if self.fetch_cve is None or stats.fetched_cves + stats.fetch_failed >= self.fetch_limit:
            return []
        try:
            recs = self.fetch_cve(cve_id)
        except Exception:  # la CVE se reintenta cuando su fuente vuelva a enviar el hecho
            stats.fetch_failed += 1
            return []
        stats.fetched_cves += 1
        return [replace(r, observed_at=at, baseline=False) for r in recs if r.cve_id == cve_id]

    # -- ejecución -----------------------------------------------------------------------------

    def save(self, result: SourceRunResult) -> tuple[int, IngestStats]:
        """Guarda la ejecución. Si es `ok`, también sus hechos nuevos y lo que digan las reglas."""
        stats = IngestStats()
        with Session(self.engine) as session, session.begin():
            run_id = self._insert_run(session, result)
            if result.status is not RunStatus.OK:
                return run_id, stats
            records = []
            for r in result.records:
                if r.share_alike:
                    stats.share_alike_dropped += 1
                else:
                    records.append(r)
            audit(self.instance, records)  # la instancia pública nunca guarda `restricted`
            batch = self._ingest(session, result, run_id, records, stats)
            session.execute(
                update(SourceRun)
                .where(SourceRun.id == run_id)
                .values(items_new=stats.stored + stats.unknown_cve)
            )
            if result.baseline_completed:
                session.execute(
                    update(Source)
                    .where(Source.name == result.source, Source.baseline_completed_at.is_(None))
                    .values(baseline_completed_at=result.finished_at)
                )
            if batch is not None:
                stats.evaluations = len(batch.evaluations)
                stats.alerts = [
                    (c.cve_id, c.level_from.label, c.level_to.label) for c in batch.alerts
                ]
        return run_id, stats

    def _ingest(
        self,
        session: Session,
        result: SourceRunResult,
        run_id: int,
        records: list[Record],
        stats: IngestStats,
    ) -> BatchResult | None:
        now = result.started_at
        by_key: dict[str, Record] = {}
        for r in records:
            by_key.setdefault(fact_key(r), r)
        seen = self._seen(session, result.source, by_key)
        known = known_cves(session, {r.cve_id for r in by_key.values()})
        known |= {r.cve_id for r in by_key.values() if r.entity is Entity.VULNERABILITY}

        to_store: list[Record] = []
        fetched: list[Record] = []
        marks: list[dict[str, Any]] = []
        for key, r in by_key.items():
            s = seen.get(key)
            if s is not None and s.stored:
                stats.duplicates += 1
                continue
            if r.cve_id not in known:
                # Solo la primera vez que se ve, y solo si puede subir el nivel tras la carga
                # inicial: si cvelistV5 no la tiene, no se reintenta en cada ejecución.
                wants_cve = (
                    s is None
                    and not r.baseline
                    and r.entity is Entity.SIGNAL
                    and r.kind in LEVEL_KINDS
                    and is_cve_id(r.cve_id)
                )
                extra = self._fetch(r.cve_id, now, stats) if wants_cve else []
                if any(x.entity is Entity.VULNERABILITY for x in extra):
                    fetched.extend(extra)
                    known.add(r.cve_id)
                else:
                    if s is None and r.source not in ENRICHMENT_ONLY:
                        self._mark(marks, result.source, key, r, run_id, stored=False)
                        stats.unknown_cve += 1
                    continue
            if s is not None:  # visto antes con su CVE desconocida: conserva su primera marca
                r = replace(r, baseline=s.baseline, observed_at=s.first_observed_at)
            self._mark(marks, result.source, key, r, run_id, stored=True)
            to_store.append(r)

        # Lo traído de cvelistV5 cuenta como hecho de cvelistV5 (si no se tenía ya).
        fetched_new: list[Record] = []
        for src in sorted({r.source for r in fetched}):
            mine = {fact_key(r): r for r in fetched if r.source == src}
            already = self._seen(session, src, mine)
            for key, r in mine.items():
                if key in already and already[key].stored:
                    continue
                self._mark(marks, src, key, r, run_id, stored=True)
                fetched_new.append(r)
        self._flush_marks(session, marks)
        to_store = fetched_new + to_store
        if not to_store:
            return None

        touched = {r.cve_id for r in to_store}
        before = load_records(session, touched)
        levels = load_levels(session, touched)
        history = load_history(session, touched, self.audience.name)
        rules = RuleEngine(self.audience, self.lists, baselines=baselines(session))
        for cve in touched:
            rules.restore(cve, before[cve], levels.get(cve, Level.NONE), history[cve])

        # Primero las CVE (claves foráneas), luego productos y señales.
        order = {Entity.VULNERABILITY: 0, Entity.AFFECTED_PRODUCT: 1, Entity.SIGNAL: 2}
        signal_ids: dict[int, int] = {}
        for r in sorted(to_store, key=lambda x: order[x.entity]):
            sid = self._store(session, r)
            if sid is not None:
                signal_ids[id(r)] = sid
        stats.stored += len(to_store)

        batch = rules.ingest(to_store, now)
        for ev in batch.evaluations:
            trigger = signal_ids.get(id(ev.trigger)) if ev.trigger is not None else None
            session.execute(insert(RuleEvaluation).values(**ev.to_row(trigger)))
        for change in batch.changes:
            self._save_change(session, change, signal_ids)
        return batch

    def _save_change(self, session: Session, change: LevelChange, signal_ids: dict) -> None:
        trigger = signal_ids.get(id(change.trigger)) if change.trigger is not None else None
        stmt = insert(Alert).values(
            alert_id=change.alert_id,
            cve_id=change.cve_id,
            level=change.level_to.label,
            reason=list(change.reason),
            status=ALERT_STATUS,
            first_published_at=change.at,
            modified_at=change.at,
        )
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=["alert_id"],
                set_={
                    "level": stmt.excluded.level,
                    "reason": stmt.excluded.reason,
                    "modified_at": stmt.excluded.modified_at,
                },
            )
        )
        session.execute(insert(AlertLevelHistory).values(**change.to_row(trigger)))


# -- feed publicado ------------------------------------------------------------------------------


def get_state(session: Session, name: str) -> dict[str, Any]:
    value = session.scalar(select(JobState.value).where(JobState.name == name))
    return dict(value or {})


def set_state(session: Session, name: str, value: Mapping[str, Any], at: datetime) -> None:
    stmt = insert(JobState).values(name=name, value=_jsonable(dict(value)), updated_at=at)
    session.execute(
        stmt.on_conflict_do_update(
            index_elements=["name"],
            set_={"value": stmt.excluded.value, "updated_at": stmt.excluded.updated_at},
        )
    )


def touched_since(session: Session, run_id: int, max_run_id: int, history_id: int) -> set[str]:
    """CVE con hechos guardados por ejecuciones posteriores a la marca o con cambios de nivel."""
    cves = set(
        session.scalars(
            select(FactSeen.cve_id)
            .where(FactSeen.stored, FactSeen.run_id > run_id, FactSeen.run_id <= max_run_id)
            .distinct()
        )
    )
    cves |= set(
        session.scalars(
            select(Alert.cve_id)
            .join(AlertLevelHistory, AlertLevelHistory.alert_id == Alert.alert_id)
            .where(AlertLevelHistory.id > history_id)
            .distinct()
        )
    )
    return cves


def max_ids(session: Session) -> tuple[int, int]:
    run = session.scalar(select(func.max(SourceRun.id))) or 0
    hist = session.scalar(select(func.max(AlertLevelHistory.id))) or 0
    return run, hist


def load_feed_records(
    session: Session, idents: Iterable[str] | None = None
) -> list[tuple[str, bytes, Level]]:
    stmt = select(FeedRecord.id, FeedRecord.body, FeedRecord.level)
    if idents is not None:
        ids = sorted(set(idents))
        if not ids:
            return []
        stmt = stmt.where(FeedRecord.id.in_(ids))
    return [(i, bytes(b), Level.parse(lv)) for i, b, lv in session.execute(stmt)]


def alerting_ids(session: Session) -> set[str]:
    """Registros publicados con nivel A, B o C."""
    return set(session.scalars(select(FeedRecord.id).where(FeedRecord.level != "none")))


def load_feed_entries(session: Session, horizon: datetime) -> dict[str, list[ChangeEntry]]:
    out: dict[str, list[ChangeEntry]] = {"all": [], "alerts": []}
    rows = session.scalars(
        select(FeedChange)
        .where(FeedChange.modified > horizon)
        .order_by(FeedChange.feed, FeedChange.modified, FeedChange.id)
    )
    for r in rows:
        out[r.feed].append(ChangeEntry(r.id, r.modified, Level.parse(r.level), r.type, r.sha256))
    return out


def last_feed_modified(session: Session) -> datetime | None:
    return session.scalar(select(func.max(FeedChange.modified)))


def save_feed(
    session: Session,
    records: Mapping[str, tuple[bytes, str, Level]],
    entries: Mapping[str, Iterable[ChangeEntry]],
    horizon: datetime,
) -> int:
    """Guarda registros publicados y entradas nuevas; poda lo que sale de la retención."""
    for ident, (body, sha, level) in records.items():
        modified = json.loads(body)["modified"]
        stmt = insert(FeedRecord).values(
            id=ident,
            cve_id=ident.removeprefix("VS-"),
            level=level.label,
            modified=datetime.fromisoformat(modified.replace("Z", "+00:00")),
            sha256=sha,
            body=body,
        )
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=["id"],
                set_={c: stmt.excluded[c] for c in ("level", "modified", "sha256", "body")},
            )
        )
    n = 0
    for feed, items in entries.items():
        for e in items:
            session.execute(
                insert(FeedChange)
                .values(
                    feed=feed,
                    modified=e.modified,
                    id=e.id,
                    level=e.level.label,
                    type=e.type,
                    sha256=e.sha256,
                )
                .on_conflict_do_nothing()
            )
            n += 1
    session.execute(delete(FeedChange).where(FeedChange.modified <= horizon))
    return n


VULN_PATH_PREFIX = "/v1/vulns/"


def load_signatures(session: Session) -> list[StoredSignature]:
    """Firmas que dejó el job de publicación (ADR-0026), para la API."""
    rows = session.execute(
        select(
            FeedSignature.path,
            FeedSignature.sha256,
            FeedSignature.jws,
            FeedSignature.kid,
            FeedSignature.body,
        )
    )
    return [
        StoredSignature(p, sha, jws, kid, None if body is None else bytes(body))
        for p, sha, jws, kid, body in rows
    ]


def signature_hashes(session: Session) -> dict[str, str]:
    """`ruta → sha256` de lo ya firmado (para no volver a firmar lo mismo)."""
    return dict(session.execute(select(FeedSignature.path, FeedSignature.sha256)).all())


def unsigned_record_ids(session: Session, limit: int) -> list[str]:
    """Registros publicados sin firma guardada de sus bytes actuales (relleno, ADR-0026)."""
    path = VULN_PATH_PREFIX + FeedRecord.id + ".json"
    signed = select(FeedSignature.path).where(
        FeedSignature.path == path, FeedSignature.sha256 == FeedRecord.sha256
    )
    stmt = select(FeedRecord.id).where(~signed.exists()).order_by(FeedRecord.id).limit(limit)
    return list(session.scalars(stmt))


def save_signatures(
    session: Session,
    signatures: Iterable[tuple[StoredSignature, datetime | None]],
    now: datetime,
) -> int:
    """Guarda (o sustituye) cada firma con su caducidad y borra las caducadas."""
    n = 0
    for s, expires in signatures:
        stmt = insert(FeedSignature).values(
            path=s.path,
            sha256=s.sha256,
            jws=s.jws,
            kid=s.kid,
            body=s.body,
            signed_at=now,
            expires_at=expires,
        )
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=["path"],
                set_={
                    c: stmt.excluded[c]
                    for c in ("sha256", "jws", "kid", "body", "signed_at", "expires_at")
                },
            )
        )
        n += 1
    session.execute(delete(FeedSignature).where(FeedSignature.expires_at <= now))
    return n


def counts(session: Session) -> dict[str, int]:
    """Recuento de filas de las tablas principales (para el informe y los logs)."""
    out = {}
    for table in (
        "vulnerability",
        "affected_product",
        "signal",
        "rule_evaluation",
        "alert",
        "feed_record",
        "feed_change",
        "source_run",
        "fact_seen",
    ):
        out[table] = session.scalar(text(f"SELECT count(*) FROM {table}"))  # noqa: S608
    return out


__all__ = [
    "Ingestor",
    "IngestStats",
    "alert_id",
    "connect",
    "counts",
    "ensure_sources",
    "fact_key",
    "load_records",
    "source_state",
]
