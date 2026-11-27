"""Servidor de la API pública sobre PostgreSQL (CMP-002).

    python -m vs.api.serve            # escucha en VS_API_HOST:VS_API_PORT (0.0.0.0:8080)

La aplicación es la de `create_app` (T6). El feed lo lee de lo que guardó el job de publicación
(`feed_record`, `feed_change`, `job_state`): `DbFeed` lo carga entero y lo recarga cuando cambia,
como mucho cada `VS_API_REFRESH` segundos (15). Las métricas salen de `metric_daily`.

Con `VS_WEB_DIST` sirve además el build del portal en el **mismo origen** (como la prueba de humo
de T8a): cualquier ruta que no sea de la API devuelve el fichero o, si no existe, `index.html`.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, Response
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from vs.api.app import ApiConfig, api_audience, create_app, error
from vs.feed.config import FeedConfig
from vs.feed.publish import FeedPublisher, FeedStatus
from vs.feed.sign import Signer
from vs.jobs.settings import Settings, SettingsError, log
from vs.metrics.store import SqlMetricsReader
from vs.model.schema import JobState
from vs.rules.lists import RuleLists
from vs.sources.health import SourceHealth
from vs.sources.run import RunStatus
from vs.store import connect, load_feed_entries, load_feed_records

PUBLISH_STATE = "publish"
API_PREFIXES = ("v1/", ".well-known/", "admin/")
NO_CACHE = "no-cache"
ASSET_CACHE = "public, max-age=31536000, immutable"


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def status_from_state(value: dict[str, Any]) -> FeedStatus | None:
    if not value.get("modified"):
        return None
    sources = tuple(
        SourceHealth(s["name"], RunStatus(s["status"]), _parse_ts(s["since"]))
        for s in value.get("sources") or []
    )
    return FeedStatus(_parse_ts(value["modified"]), sources)


class DbFeed:
    """El feed publicado, leído de la base de datos. Se comporta como un `FeedPublisher`."""

    def __init__(
        self,
        engine: Engine,
        audience,
        config: FeedConfig,
        signer: Signer,
        lists: RuleLists,
        refresh_seconds: float = 15.0,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.engine = engine
        self.audience = audience
        self.config = config
        self.signer = signer
        self.lists = lists
        self.refresh_seconds = refresh_seconds
        self.clock = clock
        self._lock = threading.Lock()
        self._checked = -1e18
        self._version: Any = None
        self._pub = self._empty()

    def _empty(self) -> FeedPublisher:
        return FeedPublisher(self.audience, self.config, self.signer, self.lists)

    def _load(self, session: Session, state: dict[str, Any]) -> FeedPublisher:
        pub = self._empty()
        horizon = self.clock() - timedelta(days=self.config.retention_days)
        pub.restore(load_feed_records(session), load_feed_entries(session, horizon))
        status = status_from_state(state)
        if status is not None:
            pub.set_status(status)
        return pub

    def current(self) -> FeedPublisher:
        with self._lock:
            now = time.monotonic()
            if now - self._checked < self.refresh_seconds:
                return self._pub
            self._checked = now
            with Session(self.engine) as session:
                row = session.execute(
                    select(JobState.value, JobState.updated_at).where(
                        JobState.name == PUBLISH_STATE
                    )
                ).first()
                version = row.updated_at if row else None
                if version != self._version:
                    self._pub = self._load(session, dict(row.value) if row else {})
                    self._version = version
                    log("feed_loaded", records=len(self._pub.published_records()))
                session.rollback()
            return self._pub

    def __getattr__(self, name: str) -> Any:
        return getattr(self.current(), name)


def is_api_path(path: str) -> bool:
    bare = path.lstrip("/")
    return bare.startswith(API_PREFIXES) or bare == "admin"


def mount_portal(app: FastAPI, dist: Path) -> None:
    """El build del portal en el mismo origen; las rutas de la SPA sirven `index.html`."""
    root = dist.resolve()
    index = root / "index.html"
    if not index.is_file():
        raise SettingsError(f"VS_WEB_DIST no tiene index.html: {root}")

    @app.get("/{path:path}", include_in_schema=False)
    def portal(path: str) -> Response:
        if is_api_path(path):
            return error(404, "not_found", "ruta de la API desconocida")
        target = (root / path).resolve() if path else index
        if not target.is_relative_to(root) or not target.is_file():
            target = index
        cache = ASSET_CACHE if target.parent.name == "assets" else NO_CACHE
        return FileResponse(target, headers={"Cache-Control": cache})


def build_app(settings: Settings, engine: Engine | None = None) -> FastAPI:
    instance = settings.instance()
    feed_cfg = settings.feed_config()
    engine = engine or connect(settings.require_db())
    audience = api_audience(instance)
    feed = DbFeed(
        engine,
        audience,
        feed_cfg,
        settings.signer(feed_cfg, required=False),
        settings.lists(),
        refresh_seconds=float(os.environ.get("VS_API_REFRESH", "15")),
    )
    cfg = ApiConfig(
        instance=instance,
        publisher=feed,  # type: ignore[arg-type] - mismo interfaz que FeedPublisher
        metrics=SqlMetricsReader(engine),
        donations_enabled=False,
    )
    app = create_app(cfg)
    if settings.web_dist is not None:
        mount_portal(app, settings.web_dist)
    return app


def main() -> int:
    import uvicorn

    settings = Settings.from_env()
    try:
        app = build_app(settings)
    except SettingsError as exc:
        log("config_error", error=str(exc))
        return 2
    host = os.environ.get("VS_API_HOST", "0.0.0.0")  # noqa: S104 - dentro del contenedor
    port = int(os.environ.get("VS_API_PORT", "8080"))
    log("api_start", host=host, port=port, portal=bool(settings.web_dist))
    uvicorn.run(app, host=host, port=port, log_level="info", proxy_headers=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
