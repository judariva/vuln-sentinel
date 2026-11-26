"""Índice de cambios del feed con cursor, páginas selladas por hora y retención (ADR-0019).

- Cada entrada lleva solo `id`, `modified`, `level`, `type` y `sha256`; el registro completo se
  sirve aparte (`/v1/vulns/{id}.json`, ETag = hash).
- Orden estable por `(modified, id)`. El cursor es opaco para el cliente: `<modified>,<id>` de la
  última entrada recibida. Se devuelven las entradas estrictamente posteriores.
- 1.000 entradas por página por defecto; como mucho 5.000.
- Las horas cerradas son páginas selladas e inmutables. La hora en curso solo se sirve como «head».
- Retención de 30 días: un cursor o una página más antiguos dan `Gone` (HTTP 410) con el enlace al
  último snapshot diario.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from vs.feed.osv import CHANGE_TYPES, ID_RE, ts
from vs.rules.levels import Level

HOUR_FMT = "%Y-%m-%dT%H"
HOUR_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}")
FEEDS = ("all", "alerts")


class CursorError(ValueError):
    """Cursor mal formado (HTTP 400)."""


class NotSealedError(ValueError):
    """La hora pedida aún no está cerrada (HTTP 404: se sirve el «head»)."""


class Gone(Exception):  # noqa: N818 - nombre del código HTTP
    """Más allá de la retención (HTTP 410). Lleva el enlace al snapshot diario."""

    status = 410

    def __init__(self, detail: str, snapshot_url: str) -> None:
        super().__init__(detail)
        self.detail = detail
        self.snapshot_url = snapshot_url

    def body(self) -> dict[str, Any]:
        return {
            "error": "gone",
            "status": 410,
            "detail": self.detail,
            "snapshot": self.snapshot_url,
        }


@dataclass(frozen=True)
class ChangeEntry:
    id: str
    modified: datetime
    level: Level
    type: str
    sha256: str

    def __post_init__(self) -> None:
        if not ID_RE.fullmatch(self.id):
            raise ValueError(f"id no válido: {self.id!r}")
        if self.type not in CHANGE_TYPES:
            raise ValueError(f"tipo de cambio no válido: {self.type!r}")
        if self.modified.tzinfo is None:
            raise ValueError("modified sin zona horaria")
        if not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ValueError("sha256 no válido")

    @property
    def key(self) -> tuple[datetime, str]:
        return (self.modified, self.id)

    @property
    def cursor(self) -> str:
        return encode_cursor(self.modified, self.id)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "modified": ts(self.modified),
            "level": self.level.label,
            "type": self.type,
            "sha256": self.sha256,
        }


def encode_cursor(modified: datetime, ident: str) -> str:
    return f"{ts(modified)},{ident}"


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    stamp, sep, ident = (cursor or "").partition(",")
    if not sep or not ID_RE.fullmatch(ident):
        raise CursorError(f"cursor no válido: {cursor!r}")
    try:
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CursorError(f"cursor no válido: {cursor!r}") from exc
    if when.tzinfo is None or not stamp.endswith("Z"):
        raise CursorError(f"cursor sin UTC: {cursor!r}")
    return when.astimezone(UTC), ident


def hour_of(when: datetime) -> str:
    return when.astimezone(UTC).strftime(HOUR_FMT)


def hour_start(hour: str) -> datetime:
    if not HOUR_RE.fullmatch(hour):
        raise ValueError(f"hora no válida: {hour!r}")
    return datetime.strptime(hour, HOUR_FMT).replace(tzinfo=UTC)


class ChangeLog:
    """Índice de un feed (`all` o `alerts`). En memoria; la persistencia la pone quien lo use."""

    def __init__(
        self, feed: str, retention: timedelta, snapshot_url: Callable[[datetime], str]
    ) -> None:
        if feed not in FEEDS:
            raise ValueError(f"feed no válido: {feed!r}")
        self.feed = feed
        self.retention = retention
        self._snapshot_url = snapshot_url
        self._entries: list[ChangeEntry] = []
        self._keys: list[tuple[datetime, str]] = []

    def __len__(self) -> int:
        return len(self._entries)

    def entries(self) -> tuple[ChangeEntry, ...]:
        return tuple(self._entries)

    @property
    def last_modified(self) -> datetime | None:
        return self._entries[-1].modified if self._entries else None

    def append(self, entry: ChangeEntry) -> None:
        """Solo se añade al final: `(modified, id)` estrictamente creciente. Así una hora cerrada
        no cambia nunca y un cursor no se salta nada."""
        if self._keys and entry.key <= self._keys[-1]:
            raise ValueError(
                f"entrada fuera de orden en '{self.feed}': {entry.key} <= {self._keys[-1]}"
            )
        self._entries.append(entry)
        self._keys.append(entry.key)

    def horizon(self, now: datetime) -> datetime:
        return now - self.retention

    def gone(self, now: datetime, what: str) -> Gone:
        return Gone(
            f"{what} más antiguo que la retención de {self.retention.days} días",
            self._snapshot_url(now),
        )

    def prune(self, now: datetime) -> int:
        """Quita lo que ya está fuera de la retención. Devuelve cuántas entradas quitó."""
        cut = bisect_right(self._keys, (self.horizon(now), "￿"))
        del self._entries[:cut]
        del self._keys[:cut]
        return cut

    def page(
        self, since: str | None, limit: int, max_limit: int, now: datetime
    ) -> tuple[list[ChangeEntry], str | None, bool]:
        """Entradas posteriores al cursor. Devuelve (entradas, cursor siguiente, ¿hay más?)."""
        if limit < 1:
            raise CursorError("limit debe ser >= 1")
        limit = min(limit, max_limit)
        horizon = self.horizon(now)
        if since:
            key = decode_cursor(since)
            if key[0] < horizon:
                raise self.gone(now, "cursor")
        else:
            key = (horizon, "")  # sin cursor se empieza en el horizonte de la retención
        start = bisect_right(self._keys, key)
        chunk = self._entries[start : start + limit]
        has_more = start + limit < len(self._entries)
        return chunk, (chunk[-1].cursor if chunk else since), has_more

    def sealed_hours(self, now: datetime) -> list[str]:
        """Horas cerradas con entradas, dentro de la retención."""
        current = hour_of(now)
        horizon_hour = hour_of(self.horizon(now))
        hours = sorted({hour_of(e.modified) for e in self._entries})
        return [h for h in hours if horizon_hour <= h < current]

    def hour_entries(self, hour: str, now: datetime) -> list[ChangeEntry]:
        """Entradas de una hora cerrada. La hora en curso no está sellada."""
        start = hour_start(hour)
        if start + timedelta(hours=1) > now:
            raise NotSealedError(f"la hora {hour} aún no está cerrada")
        if start + timedelta(hours=1) <= self.horizon(now):
            raise self.gone(now, "página")
        end = start + timedelta(hours=1)
        lo = bisect_right(self._keys, (start, ""))
        hi = bisect_right(self._keys, (end, ""))
        return [e for e in self._entries[lo:hi] if start <= e.modified < end]
