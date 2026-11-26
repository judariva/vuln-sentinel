"""API pública de solo lectura (CMP-002; PLAN.md §3, §9 y §10; ADR-0019).

Sirve lo que publica `FeedPublisher` (T5) y las métricas precalculadas en `metric_daily`:

- `/v1/feed/{all,alerts}/changes?since=&limit=` (+ `.jws`): índice con cursor, TTL de 60 s; `410`
  más allá de la retención, `400` con un cursor mal formado.
- `/v1/feed/alerts/latest.json` (+ `.jws`).
- `/v1/vulns/{id}.json` (+ `.jws`): registro OSV completo, `ETag` igual a su hash; `304` con
  `If-None-Match`.
- `/v1/digest/{fecha}.json` (+ `.jws`): resumen de un día cerrado, inmutable.
- `/.well-known/vuln-sentinel/keys.json`: JWKS con rotación por `kid`.
- `/v1/metrics/daily.json` y `/v1/metrics/cost.json`: desde `metric_daily`. Con las donaciones
  desactivadas no sale ningún dato de donaciones.
- `/admin/*`: esqueleto. Exige el JWT de Access y no tiene lógica (501).

Reglas:
- **Solo lectura.** Las rutas públicas solo admiten `GET`. Nada escribe en la base de datos ni en
  el publicador.
- **Audiencia de la instancia.** La API pública sirve el feed de la audiencia `public` de la
  instancia (solo `open`). Si el publicador es de otra audiencia o admite `restricted`, la
  aplicación no arranca.
- Toda respuesta lleva `X-VS-Schema`. Los hosts salen de la configuración (ADR-0016).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import Response

from vs.api.access import HEADER as ACCESS_HEADER
from vs.api.access import AccessConfig, AccessError, AccessVerifier
from vs.api.digest import DayNotClosedError, build_digest
from vs.feed.changes import FEEDS, CursorError, Gone
from vs.feed.config import FEED_SCHEMA_VERSION
from vs.feed.osv import ID_RE, canonical_bytes, sha256_hex
from vs.feed.publish import HEAD, IMMUTABLE, JSON, Document, FeedPublisher
from vs.feed.rights import Audience, audience_for
from vs.feed.sign import Signer
from vs.instance import Instance
from vs.metrics.store import (
    COST_EUR,
    DONATIONS_COUNT,
    DONATIONS_SATS,
    METRIC_RE,
    MetricRow,
    MetricsReader,
    is_donation_metric,
)
from vs.sources.base import LicenseClass

PUBLIC_AUDIENCE = "public"
READ_METHODS = frozenset({"GET"})
NO_STORE = "no-store"
DEFAULT_METRIC_DAYS = 30
MAX_METRIC_DAYS = 366
DEFAULT_COST_MONTHS = 12
MAX_COST_MONTHS = 36
MONTH_RE = re.compile(r"\d{4}-\d{2}")


class ApiConfigError(ValueError):
    """La configuración de la API no es válida: la aplicación no arranca."""


class BadRequestError(ValueError):
    """Parámetro no válido (HTTP 400)."""


@dataclass
class ApiConfig:
    instance: Instance
    publisher: FeedPublisher
    metrics: MetricsReader
    access: AccessVerifier = field(default_factory=lambda: AccessVerifier(AccessConfig()))
    donations_enabled: bool = False
    previous_signers: tuple[Signer, ...] = ()
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))


def api_audience(instance: Instance) -> Audience:
    """Audiencia de la API pública: la `public` de la instancia, sin licencias (solo `open`)."""
    return audience_for(instance, PUBLIC_AUDIENCE)


def check_config(cfg: ApiConfig) -> None:
    expected = api_audience(cfg.instance)
    aud = cfg.publisher.audience
    if LicenseClass.RESTRICTED in getattr(aud, "license_classes", ()):
        raise ApiConfigError("la API pública no puede servir un feed que admite 'restricted'")
    if aud != expected:
        raise ApiConfigError(
            f"el publicador es de la audiencia {aud!r}; la API pública sirve {expected!r}"
        )


# -- respuestas ------------------------------------------------------------------------------------


def _etag_matches(header: str | None, etag: str | None) -> bool:
    if not header or not etag:
        return False
    if header.strip() == "*":
        return True
    return etag in {t.strip().removeprefix("W/") for t in header.split(",")}


def send(request: Request, doc: Document) -> Response:
    headers = dict(doc.headers)
    headers.setdefault("X-VS-Schema", FEED_SCHEMA_VERSION)
    media = headers.pop("Content-Type", JSON)
    if doc.status == 200 and _etag_matches(
        request.headers.get("if-none-match"), headers.get("ETag")
    ):
        keep = {k: v for k, v in headers.items() if k in ("ETag", "Cache-Control", "X-VS-Schema")}
        return Response(status_code=304, headers=keep)
    if doc.status != 200:
        headers["Cache-Control"] = NO_STORE
    return Response(content=doc.body, status_code=doc.status, headers=headers, media_type=media)


def json_document(path: str, doc: Any, cache: str | None, status: int = 200) -> Document:
    body = canonical_bytes(doc)
    headers = {"Content-Type": JSON, "X-VS-Schema": FEED_SCHEMA_VERSION}
    if status == 200:
        headers["ETag"] = f'"{sha256_hex(body)}"'
    headers["Cache-Control"] = cache if cache and status == 200 else NO_STORE
    return Document(path, body, headers, status)


def error(status: int, code: str, detail: str, extra: Mapping[str, Any] | None = None) -> Response:
    doc = {"error": code, "status": status, "detail": detail, **(extra or {})}
    return Response(
        content=canonical_bytes(doc),
        status_code=status,
        media_type=JSON,
        headers={"Cache-Control": NO_STORE, "X-VS-Schema": FEED_SCHEMA_VERSION},
    )


# -- parámetros ------------------------------------------------------------------------------------


def _limit(raw: str | None) -> int | None:
    if raw is None:
        return None
    if not raw.isdigit():
        raise BadRequestError("limit debe ser un entero positivo")
    return int(raw)


def _day(raw: str, name: str) -> date:
    try:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
            raise ValueError(raw)
        return date.fromisoformat(raw)
    except ValueError:
        raise BadRequestError(f"{name} debe ser una fecha AAAA-MM-DD") from None


def _month(raw: str, name: str) -> date:
    if not MONTH_RE.fullmatch(raw):
        raise BadRequestError(f"{name} debe ser un mes AAAA-MM")
    try:
        return date.fromisoformat(raw + "-01")
    except ValueError:
        raise BadRequestError(f"{name} debe ser un mes AAAA-MM") from None


def _add_months(month: date, n: int) -> date:
    idx = month.year * 12 + month.month - 1 + n
    return date(idx // 12, idx % 12 + 1, 1)


def _months_between(a: date, b: date) -> int:
    return (b.year - a.year) * 12 + b.month - a.month + 1


def day_range(raw_from: str | None, raw_to: str | None, today: date) -> tuple[date, date]:
    end = _day(raw_to, "to") if raw_to else today - timedelta(days=1)
    start = _day(raw_from, "from") if raw_from else end - timedelta(days=DEFAULT_METRIC_DAYS - 1)
    if start > end:
        raise BadRequestError("from es posterior a to")
    if (end - start).days + 1 > MAX_METRIC_DAYS:
        raise BadRequestError(f"como mucho {MAX_METRIC_DAYS} días por consulta")
    return start, end


def month_range(raw_from: str | None, raw_to: str | None, today: date) -> tuple[date, date]:
    end = _month(raw_to, "to") if raw_to else today.replace(day=1)
    start = _month(raw_from, "from") if raw_from else _add_months(end, -(DEFAULT_COST_MONTHS - 1))
    if start > end:
        raise BadRequestError("from es posterior a to")
    if _months_between(start, end) > MAX_COST_MONTHS:
        raise BadRequestError(f"como mucho {MAX_COST_MONTHS} meses por consulta")
    return start, end


# -- métricas --------------------------------------------------------------------------------------


def visible_rows(rows: Iterable[MetricRow], donations_enabled: bool) -> list[MetricRow]:
    return [r for r in rows if donations_enabled or not is_donation_metric(r.metric)]


def cost_document(
    rows: Iterable[MetricRow], start: date, end: date, donations_enabled: bool
) -> dict[str, Any]:
    """Coste real por mes frente a lo recibido (§9). Sin donaciones activas, solo el coste."""
    months: dict[str, dict[str, Any]] = {}
    m = start
    while m <= end:
        key = m.strftime("%Y-%m")
        item: dict[str, Any] = {"month": key, "cost_eur": 0.0, "cost_by_provider": {}}
        if donations_enabled:
            item.update(donations_sats=0, donations_count=0, donations_by_channel={})
        months[key] = item
        m = _add_months(m, 1)
    for r in rows:
        item = months.get(r.day.strftime("%Y-%m"))
        if item is None:
            continue
        if r.metric == COST_EUR:
            item["cost_eur"] += r.value
            prov = item["cost_by_provider"]
            prov[r.dimension or "other"] = prov.get(r.dimension or "other", 0.0) + r.value
        elif donations_enabled and r.metric == DONATIONS_SATS:
            item["donations_sats"] += int(r.value)
            ch = item["donations_by_channel"]
            ch[r.dimension] = ch.get(r.dimension, 0) + int(r.value)
        elif donations_enabled and r.metric == DONATIONS_COUNT:
            item["donations_count"] += int(r.value)
    for item in months.values():
        item["cost_eur"] = round(item["cost_eur"], 4)
        item["cost_by_provider"] = {
            k: round(v, 4) for k, v in sorted(item["cost_by_provider"].items())
        }
        if donations_enabled:
            item["donations_by_channel"] = dict(sorted(item["donations_by_channel"].items()))
    return {
        "schema_version": FEED_SCHEMA_VERSION,
        "kind": "cost",
        "currency": "EUR",
        "from": start.strftime("%Y-%m"),
        "to": end.strftime("%Y-%m"),
        "months": list(months.values()),
    }


# -- aplicación ------------------------------------------------------------------------------------


def create_app(cfg: ApiConfig) -> FastAPI:
    check_config(cfg)
    pub = cfg.publisher
    app = FastAPI(
        title="vuln-sentinel",
        version=FEED_SCHEMA_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def common_headers(request: Request, call_next):
        if request.method not in READ_METHODS and not request.url.path.startswith("/admin"):
            response = error(405, "method_not_allowed", "API de solo lectura: solo GET")
            response.headers["Allow"] = "GET"
        else:
            response = await call_next(request)
        response.headers.setdefault("X-VS-Schema", FEED_SCHEMA_VERSION)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response

    # -- feed ----------------------------------------------------------------------------------

    def changes_doc(feed: str, since: str | None, limit: str | None) -> Document | Response:
        if feed not in FEEDS:
            return error(404, "not_found", f"feed no válido: {feed}")
        now = cfg.clock()
        try:
            return pub.changes_head(feed, since, now, _limit(limit))
        except Gone as exc:
            return pub.gone_document(f"/v1/feed/{feed}/changes", exc)
        except (CursorError, BadRequestError) as exc:
            return error(400, "bad_request", str(exc))

    def maybe_signed(request: Request, doc: Document | Response, jws: bool) -> Response:
        if isinstance(doc, Response):
            return doc
        if jws and doc.status == 200:
            doc = pub.signature(doc)
        return send(request, doc)

    @app.get("/v1/feed/{feed}/changes")
    def feed_changes(request: Request, feed: str):
        q = request.query_params
        return maybe_signed(request, changes_doc(feed, q.get("since"), q.get("limit")), jws=False)

    @app.get("/v1/feed/{feed}/changes.jws")
    def feed_changes_jws(request: Request, feed: str):
        q = request.query_params
        return maybe_signed(request, changes_doc(feed, q.get("since"), q.get("limit")), jws=True)

    @app.get("/v1/feed/alerts/latest.json")
    def alerts_latest(request: Request):
        return send(request, pub.alerts_latest(cfg.clock()))

    @app.get("/v1/feed/alerts/latest.json.jws")
    def alerts_latest_jws(request: Request):
        return send(request, pub.signature(pub.alerts_latest(cfg.clock())))

    def vuln_doc(ident: str) -> Document | Response:
        if not ID_RE.fullmatch(ident):
            return error(404, "not_found", "id no válido")
        try:
            return pub.vuln(ident)
        except KeyError:
            return error(404, "not_found", f"{ident} no está en el feed")

    @app.get("/v1/vulns/{ident}.json")
    def vuln(request: Request, ident: str):
        return maybe_signed(request, vuln_doc(ident), jws=False)

    @app.get("/v1/vulns/{ident}.json.jws")
    def vuln_jws(request: Request, ident: str):
        return maybe_signed(request, vuln_doc(ident), jws=True)

    def digest_doc(raw_day: str) -> Document | Response:
        path = f"/v1/digest/{raw_day}.json"
        try:
            day = _day(raw_day, "fecha")
            doc = build_digest(pub.logs["all"], day, cfg.clock())
        except BadRequestError as exc:
            return error(400, "bad_request", str(exc))
        except DayNotClosedError as exc:
            return error(404, "not_found", str(exc))
        except Gone as exc:
            return pub.gone_document(path, exc)
        return json_document(path, doc, IMMUTABLE)

    @app.get("/v1/digest/{raw_day}.json")
    def digest(request: Request, raw_day: str):
        return maybe_signed(request, digest_doc(raw_day), jws=False)

    @app.get("/v1/digest/{raw_day}.json.jws")
    def digest_jws(request: Request, raw_day: str):
        return maybe_signed(request, digest_doc(raw_day), jws=True)

    @app.get("/.well-known/vuln-sentinel/keys.json")
    def keys(request: Request):
        return send(request, pub.keys(cfg.previous_signers))

    # -- métricas ------------------------------------------------------------------------------

    @app.get("/v1/metrics/daily.json")
    def metrics_daily(request: Request):
        q = request.query_params
        today = cfg.clock().date()
        try:
            start, end = day_range(q.get("from"), q.get("to"), today)
        except BadRequestError as exc:
            return error(400, "bad_request", str(exc))
        wanted = q.getlist("metric") or None
        if wanted:
            bad = [m for m in wanted if not METRIC_RE.fullmatch(m)]
            if bad:
                return error(400, "bad_request", f"métrica no válida: {bad[0]!r}")
            if not cfg.donations_enabled and any(is_donation_metric(m) for m in wanted):
                return error(404, "not_found", "métrica no disponible")
        rows = visible_rows(cfg.metrics.rows(start, end, wanted), cfg.donations_enabled)
        doc = {
            "schema_version": FEED_SCHEMA_VERSION,
            "kind": "metrics_daily",
            "from": start.isoformat(),
            "to": end.isoformat(),
            "rows": [r.to_json() for r in rows],
        }
        return send(request, json_document("/v1/metrics/daily.json", doc, HEAD))

    @app.get("/v1/metrics/cost.json")
    def metrics_cost(request: Request):
        q = request.query_params
        today = cfg.clock().date()
        try:
            start, end = month_range(q.get("from"), q.get("to"), today)
        except BadRequestError as exc:
            return error(400, "bad_request", str(exc))
        names = [COST_EUR]
        if cfg.donations_enabled:
            names += [DONATIONS_SATS, DONATIONS_COUNT]
        last = _add_months(end, 1) - timedelta(days=1)
        rows = visible_rows(cfg.metrics.rows(start, last, names), cfg.donations_enabled)
        doc = cost_document(rows, start, end, cfg.donations_enabled)
        return send(request, json_document("/v1/metrics/cost.json", doc, HEAD))

    # -- salud (probes de Container Apps) ------------------------------------------------------

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        # Liveness y readiness: el proceso responde. No toca la base de datos ni el publicador,
        # para que una fuente o la BD caídas no reinicien la réplica (fail-closed va en el feed).
        return Response(b'{"status":"ok"}', media_type=JSON, headers={"Cache-Control": NO_STORE})

    # -- administración (esqueleto) -----------------------------------------------------------

    @app.api_route("/admin", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    @app.api_route("/admin/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def admin(request: Request, rest: str = ""):
        try:
            cfg.access.verify(request.headers.get(ACCESS_HEADER))
        except AccessError as exc:
            return error(
                exc.status, "unauthorized" if exc.status == 401 else "forbidden", exc.detail
            )
        return error(501, "not_implemented", "administración sin implementar")

    return app
