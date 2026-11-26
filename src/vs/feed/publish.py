"""Publicador del feed de una audiencia: registros, feed completo, feed de alertas y firma.

ADR-0019: dos feeds sobre el mismo modelo. `all` lleva toda CVE nueva o cambiada con su nivel
(`A`, `B`, `C` o `none`); `alerts`, solo las que tienen nivel A, B o C (y la bajada manual de una
que lo tenía, para que el consumidor la vea).

ADR-0022: cada publicador trabaja para **una audiencia**. Todo registro que la audiencia no puede
recibir se descarta antes de construir el documento, así que ni el registro ni su nivel dependen
de datos que esa audiencia no puede ver.

ADR-0008: cada documento sale como bytes exactos (`Document.body`) y su firma JWS detached se
sirve en la misma ruta con `.jws`.

Todo en memoria: la persistencia (PostgreSQL) y la escritura en R2 quedan fuera de esta tarea.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from vs.feed.changes import (
    ChangeEntry,
    ChangeLog,
    CursorError,
    Gone,
    hour_of,
)
from vs.feed.config import FEED_SCHEMA_VERSION, HEAD_TTL_SECONDS, FeedConfig
from vs.feed.osv import (
    CHANGE_TYPES,
    alert_id,
    build_record,
    canonical_bytes,
    sha256_hex,
    ts,
)
from vs.feed.sign import Signer, jwks, sign_detached
from vs.rules.engine import AudienceLike, LevelChange, RuleEngine, assess
from vs.rules.levels import Level
from vs.rules.lists import EMPTY_LISTS, RuleLists
from vs.sources.base import Record
from vs.sources.health import SourceHealth

JSON = "application/json"
JWS = "application/jose"
IMMUTABLE = "public, max-age=31536000, immutable"
HEAD = f"public, max-age={HEAD_TTL_SECONDS}"
KEYS_PATH = "/.well-known/vuln-sentinel/keys.json"
_TICK = timedelta(microseconds=1)


@dataclass(frozen=True)
class Document:
    """Un documento publicable: ruta, bytes exactos y cabeceras HTTP."""

    path: str
    body: bytes
    headers: Mapping[str, str]
    status: int = 200

    @property
    def sha256(self) -> str:
        return sha256_hex(self.body)


@dataclass
class _Published:
    record: dict[str, Any]
    body: bytes
    sha256: str
    level: Level


@dataclass(frozen=True)
class FeedStatus:
    """Estado del monitor que lleva el índice «head» para el vigilante externo (PLAN §11).

    `modified` es el final de la última ejecución completa del job de publicación, haya cambiado
    algo o no: así un día tranquilo no parece un monitor parado. `sources` es la salud de cada
    fuente (`vs.sources.health`), con las que están en UNKNOWN y desde cuándo.
    """

    modified: datetime
    sources: tuple[SourceHealth, ...]

    def __post_init__(self) -> None:
        if self.modified.tzinfo is None:
            raise ValueError("modified sin zona horaria")
        names = [s.source for s in self.sources]
        if len(names) != len(set(names)):
            raise ValueError(f"fuentes repetidas en el estado: {names}")

    def to_json(self) -> dict[str, Any]:
        return {
            "modified": ts(self.modified),
            "sources": [s.to_json() for s in sorted(self.sources, key=lambda s: s.source)],
        }


@dataclass
class PublishStats:
    dropped_by_rights: int = 0
    dropped_share_alike: int = 0
    unchanged: int = 0
    published: int = 0
    by_type: dict[str, int] = field(default_factory=dict)


def _content(record: Mapping[str, Any]) -> bytes:
    """Lo que define si un registro ha cambiado: todo salvo `modified` y la lista de cambios."""
    doc = {k: v for k, v in record.items() if k != "modified"}
    ext = dict(doc["database_specific"]["vuln_sentinel"])
    ext.pop("changes", None)
    doc["database_specific"] = {**doc["database_specific"], "vuln_sentinel": ext}
    return canonical_bytes(doc)


def _ranges(record: Mapping[str, Any]) -> bool:
    return any(a.get("ranges") or a.get("versions") for a in record.get("affected") or [])


def classify(
    prev: Mapping[str, Any] | None,
    new: Mapping[str, Any],
    epss_jump: float | None = None,
) -> list[str]:
    """Tipos de cambio entre dos versiones del registro, en orden de prioridad (PLAN.md §3).

    `epss_jump` es el umbral de salto de EPSS; sin umbral no se emite (lo decide Juan).
    """
    if prev is None:
        return ["new"]
    p = prev["database_specific"]["vuln_sentinel"]
    n = new["database_specific"]["vuln_sentinel"]
    out = []
    if new.get("withdrawn") and not prev.get("withdrawn"):
        out.append("withdrawn")
    if Level.parse(n["level"]) > Level.parse(p["level"]):
        out.append("level_up")
    if n["signals"]["kev"]["cisa"] and not p["signals"]["kev"]["cisa"]:
        out.append("kev_added")
    if len(n["signals"]["exploits"]) > len(p["signals"]["exploits"]):
        out.append("poc_added")
    if set(n["signals"]["fix"]["versions"]) - set(p["signals"]["fix"]["versions"]):
        out.append("fix_released")
    if _ranges(new) and not _ranges(prev):
        out.append("range_completed")
    if epss_jump is not None:
        delta = (n["signals"].get("epss") or {}).get("delta_7d")
        before = (p["signals"].get("epss") or {}).get("delta_7d")
        if delta is not None and delta >= epss_jump and (before is None or before < epss_jump):
            out.append("epss_jump")
    out = out or ["updated"]
    return sorted(out, key=CHANGE_TYPES.index)


class FeedPublisher:
    """Feed completo y de alertas de **una audiencia**, firmados."""

    def __init__(
        self,
        audience: AudienceLike,
        config: FeedConfig,
        signer: Signer,
        lists: RuleLists = EMPTY_LISTS,
        epss_jump: float | None = None,
    ) -> None:
        if signer.kid != config.key_id:
            raise ValueError(f"el kid del firmante ({signer.kid}) no es el de la configuración")
        self.audience = audience
        self.config = config
        self.signer = signer
        self.lists = lists
        self.epss_jump = epss_jump
        self.stats = PublishStats()
        retention = timedelta(days=config.retention_days)
        self.logs = {
            "all": ChangeLog("all", retention, self.snapshot_url),
            "alerts": ChangeLog("alerts", retention, self.snapshot_url),
        }
        self._records: dict[str, _Published] = {}
        self._last: datetime | None = None
        self.status: FeedStatus | None = None

    # -- utilidades -----------------------------------------------------------------------------

    def snapshot_url(self, now: datetime) -> str:
        """Último snapshot diario completo (el del día anterior)."""
        day = (now - timedelta(days=1)).date().isoformat()
        return self.config.url(f"/v1/feed/all/snapshot/{day}.zip")

    def _allowed(self, records: Iterable[Record]) -> list[Record]:
        out = []
        for r in records:
            if not self.audience.allows(r):
                self.stats.dropped_by_rights += 1
            elif r.share_alike and not self.config.include_share_alike:
                self.stats.dropped_share_alike += 1
            else:
                out.append(r)
        return out

    def _tick(self, now: datetime) -> datetime:
        """`modified` estrictamente creciente en todo el feed: el índice nunca se reordena."""
        when = now if self._last is None or now > self._last else self._last + _TICK
        self._last = when
        return when

    # -- publicación ----------------------------------------------------------------------------

    def publish(
        self,
        cve_id: str,
        records: Iterable[Record],
        level: Level,
        history: Sequence[LevelChange],
        now: datetime,
    ) -> ChangeEntry | None:
        """Publica (o actualiza) el registro de una CVE. None si no hay nada nuevo que publicar."""
        ident = alert_id(cve_id)
        allowed = [r for r in self._allowed(records) if r.cve_id == cve_id]
        if not allowed:
            return None
        foreign = {c.feed for c in history} - {self.audience.name}
        if foreign:
            raise ValueError(f"historial de niveles de otro feed: {sorted(foreign)}")
        history = [c for c in history if c.cve_id == cve_id]
        assessment = assess(cve_id, allowed, self.lists)
        reason = list(history[-1].reason) if history and level is not Level.NONE else []
        prev = self._records.get(ident)
        published = (
            datetime.fromisoformat(prev.record["published"].replace("Z", "+00:00")) if prev else now
        )

        def build(modified: datetime, changes: list[dict[str, Any]]) -> dict[str, Any]:
            return build_record(
                cve_id,
                allowed,
                level=level,
                level_reason=reason,
                impact_class=assessment.impact_class.value,
                history=history,
                changes=changes,
                published=published,
                modified=modified,
                lists=self.lists,
            )

        old_changes = prev.record["database_specific"]["vuln_sentinel"]["changes"] if prev else []
        draft = build(now, old_changes)
        if prev is not None and _content(draft) == _content(prev.record):
            self.stats.unchanged += 1
            return None

        modified = self._tick(now)
        types = classify(prev.record if prev else None, draft, self.epss_jump)
        new_changes = []
        for t in types:
            change: dict[str, Any] = {"type": t, "at": ts(modified)}
            if t == "level_up" or (t == "updated" and prev and prev.level != level):
                change.update(level_from=prev.level.label if prev else "none", level_to=level.label)
            new_changes.append(change)
        record = build(modified, [*old_changes, *new_changes])
        body = canonical_bytes(record)
        digest = sha256_hex(body)
        entry = ChangeEntry(ident, modified, level, types[0], digest)
        self.logs["all"].append(entry)
        if level is not Level.NONE or (prev is not None and prev.level is not Level.NONE):
            self.logs["alerts"].append(entry)
        self._records[ident] = _Published(record, body, digest, level)
        self.stats.published += 1
        self.stats.by_type[types[0]] = self.stats.by_type.get(types[0], 0) + 1
        return entry

    def publish_from_engine(
        self, engine: RuleEngine, now: datetime, cve_ids: Iterable[str] | None = None
    ) -> list[ChangeEntry]:
        """Publica las CVE del motor de reglas del mismo feed, con su nivel publicado."""
        if engine.audience.name != self.audience.name:
            raise ValueError(
                f"el motor es del feed '{engine.audience.name}', no de '{self.audience.name}'"
            )
        ids = sorted(cve_ids) if cve_ids is not None else engine.cve_ids()
        out = []
        for cve in ids:
            entry = self.publish(cve, engine.records(cve), engine.level(cve), engine.history, now)
            if entry is not None:
                out.append(entry)
        return out

    def prune(self, now: datetime) -> int:
        return sum(log.prune(now) for log in self.logs.values())

    def set_status(self, status: FeedStatus) -> None:
        """Lo fija el job de publicación al terminar cada ejecución. Nunca retrocede."""
        if self.status is not None and status.modified < self.status.modified:
            raise ValueError("el estado del feed no puede retroceder en el tiempo")
        self.status = status

    # -- documentos -----------------------------------------------------------------------------

    def _json(self, path: str, doc: Any, cache: str | None = None, status: int = 200) -> Document:
        body = canonical_bytes(doc)
        headers = {
            "Content-Type": JSON,
            "X-VS-Schema": FEED_SCHEMA_VERSION,
            "ETag": f'"{sha256_hex(body)}"',
        }
        if cache:
            headers["Cache-Control"] = cache
        return Document(path, body, headers, status)

    def signature(self, doc: Document) -> Document:
        """Firma JWS detached de los bytes exactos del documento, en `<ruta>.jws`."""
        jws = sign_detached(doc.body, self.signer).encode("ascii")
        headers = {"Content-Type": JWS, "X-VS-Schema": FEED_SCHEMA_VERSION}
        if "Cache-Control" in doc.headers:
            headers["Cache-Control"] = doc.headers["Cache-Control"]
        return Document(doc.path + ".jws", jws, headers, doc.status)

    def signed(self, doc: Document) -> tuple[Document, Document]:
        return doc, self.signature(doc)

    def record(self, ident: str) -> dict[str, Any]:
        return self._records[ident].record

    def vuln(self, ident: str) -> Document:
        """`/v1/vulns/{id}.json`: el registro OSV completo, con ETag igual a su hash."""
        pub = self._records[ident]
        headers = {
            "Content-Type": JSON,
            "X-VS-Schema": FEED_SCHEMA_VERSION,
            "ETag": f'"{pub.sha256}"',
        }
        return Document(f"/v1/vulns/{ident}.json", pub.body, headers)

    def _log(self, feed: str) -> ChangeLog:
        try:
            return self.logs[feed]
        except KeyError:
            raise ValueError(f"feed no válido: {feed!r}") from None

    def changes_head(
        self, feed: str, since: str | None, now: datetime, limit: int | None = None
    ) -> Document:
        """`/v1/feed/{feed}/changes?since=`: página con cursor. TTL de 60 s.

        Lanza `Gone` si el cursor es más antiguo que la retención y `CursorError` si no es válido.
        """
        log = self._log(feed)
        limit = self.config.page_limit if limit is None else limit
        entries, nxt, more = log.page(since, limit, self.config.max_page_limit, now)
        doc = {
            "schema_version": FEED_SCHEMA_VERSION,
            "kind": "changes",
            "feed": feed,
            "sealed": False,
            "generated_at": ts(now),
            "entries": [e.to_json() for e in entries],
            "next": nxt,
            "has_more": more,
        }
        if self.status is not None:
            # `modified` y `sources` los lee el vigilante externo (PLAN §11, `vs.watchdog`).
            doc.update(self.status.to_json())
        return self._json(f"/v1/feed/{feed}/changes", doc, HEAD)

    def sealed_page(self, feed: str, hour: str, now: datetime) -> Document:
        """`/v1/feed/{feed}/changes/{AAAA-MM-DDTHH}.json`: hora cerrada, inmutable."""
        entries = self._log(feed).hour_entries(hour, now)
        doc = {
            "schema_version": FEED_SCHEMA_VERSION,
            "kind": "changes",
            "feed": feed,
            "sealed": True,
            "hour": hour,
            "entries": [e.to_json() for e in entries],
        }
        return self._json(f"/v1/feed/{feed}/changes/{hour}.json", doc, IMMUTABLE)

    def sealed_pages(self, feed: str, now: datetime) -> list[Document]:
        """Todas las horas cerradas dentro de la retención (lo que se escribe en R2)."""
        return [self.sealed_page(feed, h, now) for h in self._log(feed).sealed_hours(now)]

    def current_hour(self, now: datetime) -> str:
        return hour_of(now)

    def alerts_latest(self, now: datetime) -> Document:
        """`/v1/feed/alerts/latest.json`: estado actual de las alertas (A, B y C)."""
        alerts = [
            {
                "id": ident,
                "modified": pub.record["modified"],
                "level": pub.level.label,
                "sha256": pub.sha256,
            }
            for ident, pub in self._records.items()
            if pub.level is not Level.NONE
        ]
        alerts.sort(key=lambda a: (-Level.parse(a["level"]), a["id"]))
        doc = {
            "schema_version": FEED_SCHEMA_VERSION,
            "kind": "alerts_latest",
            "feed": "alerts",
            "generated_at": ts(now),
            "alerts": alerts,
        }
        return self._json("/v1/feed/alerts/latest.json", doc, HEAD)

    def gone_document(self, path: str, exc: Gone) -> Document:
        return self._json(path, exc.body(), status=410)

    def keys(self, previous: Iterable[Signer] = ()) -> Document:
        """JWKS público con la clave activa y las anteriores aún válidas (rotación por `kid`)."""
        return self._json(KEYS_PATH, jwks([self.signer, *previous]), HEAD)


__all__ = [
    "CursorError",
    "Document",
    "FeedPublisher",
    "FeedStatus",
    "Gone",
    "PublishStats",
    "classify",
]
