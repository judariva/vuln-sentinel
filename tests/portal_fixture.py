"""API con fixtures para la prueba de humo del portal (T8a). No es un test: lo lanza Playwright.

    uv run python -m tests.portal_fixture --port 8787 --static web/dist

Sirve en el **mismo origen** la API pública (`create_app`, la de T6) y el build del portal, así la
prueba no depende de CORS ni de ningún host. Datos: el montaje de `tests/test_feed.py` (C → B → A,
una CVE `none` y una cuyo único A es `restricted`) más una CVE en C y otra en B, todas ficticias
(`CVE-2099-*`), y métricas sintéticas de `metric_daily`. Reloj fijo.

Con `--volume N` (T8c) se suman N CVE sintéticas al día (`CVE-2099-2000…`), casi todas `none` y unas
pocas A, B y C, repartidas cada 10 minutos: el embudo y las capturas con un día realista. Los tests
de humo siguen con el montaje base (`--volume 0`, por defecto).

Sin dependencias nuevas: servidor HTTP de la biblioteca estándar que reenvía `/v1/`, `/.well-known/`
y `/admin` al `TestClient` de la aplicación, en proceso. Solo para pruebas locales y CI.
"""

from __future__ import annotations

import argparse
import gzip
import mimetypes
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fastapi.testclient import TestClient

from tests.test_feed import (
    CVE_EXPOSED,
    CVE_OTHER,
    CVE_RESTRICTED,
    T1,
    T2,
    T3,
    cve5_affected,
    epss,
    ghsa_affected,
    kev,
    make,
    msf,
    osv_affected,
    ssvc,
    vuln,
    vulncheck,
)
from vs.api import ApiConfig, create_app
from vs.api.access import AccessConfig, AccessVerifier
from vs.instance import load_instance
from vs.metrics.store import MemoryMetricsReader, MetricRow

ROOT = Path(__file__).resolve().parents[1]
INSTANCE = load_instance(ROOT / "config" / "instance.public.yaml")
NOW = datetime(2099, 3, 1, 18, 0, tzinfo=UTC)  # «hoy» es el 2099-03-01 (T1..T3)
CVE_C = "CVE-2099-1004"  # producto expuesto, RCE sin auth, sin exploit: C
CVE_B = "CVE-2099-1005"  # producto expuesto, RCE sin auth, exploit a T2: C y luego B
PROXIED = ("/v1/", "/.well-known/", "/admin/")
PROXIED_EXACT = ("/admin",)  # `/admin` sin barra también es de la API; `/administracion` no


def compressible(ctype: str) -> bool:
    """Tipos de texto que se sirven con gzip (HTML, JS, CSS, JSON, SVG)."""
    return ctype.startswith("text/") or ctype in (
        "application/javascript",
        "application/json",
        "image/svg+xml",
    )


def is_api(path: str) -> bool:
    """¿La petición es de la API? Por segmentos, no por prefijo de cadena."""
    bare = path.split("?", 1)[0]
    return bare.startswith(PROXIED) or bare in PROXIED_EXACT


# Volumen (T8c): CVE sintéticas que se suman al montaje base para que el embudo y las capturas se
# parezcan a un día real (cientos de CVE con cambios y pocas alertas). Deterministas: el mismo
# `volume` da siempre el mismo feed. Los IDs son ficticios (CVE-2099-2000…; en el feed, VS-CVE-…).
VOLUME_SHOTS = 240  # el de las capturas del embudo
VOLUME_FIRST = 2000
VOLUME_LEVELS = {  # índice → nivel; el resto, `none`
    **dict.fromkeys((17, 133), "A"),
    **dict.fromkeys((5, 61, 150, 201), "B"),
    **dict.fromkeys((29, 88, 112, 177, 230), "C"),
}
VOLUME_STEP = timedelta(minutes=10)


def volume_cve(i: int) -> str:
    return f"CVE-2099-{VOLUME_FIRST + i}"


def volume_records(i: int, at: datetime) -> list:
    """Registros de la CVE `i` del volumen, observados a `at`, según su nivel en VOLUME_LEVELS.

    `none`: producto fuera de las listas. C: producto expuesto con RCE sin auth (como CVE_C).
    B: además, exploit de Metasploit. A: además, entra en CISA KEV.
    """
    cve = volume_cve(i)
    level = VOLUME_LEVELS.get(i, "none")
    if level == "none":
        return [vuln(cve, published=at, observed=at, product="Unlisted")]
    recs = [vuln(cve, published=at, observed=at), cve5_affected(cve, at), ssvc(cve, at)]
    if level in ("A", "B"):
        recs.append(msf(cve, at))
    if level == "A":
        recs.append(kev(cve, at))
    return recs


def volume_batches(volume: int) -> dict[datetime, list]:
    """Las CVE del volumen, en tandas cada 10 minutos entre T1 y NOW (sin llegar a NOW)."""
    slots = int((NOW - T1) / VOLUME_STEP) - 1  # 28
    stride = 11  # coprimo con `slots`: recorre todas las tandas
    batches: dict[datetime, list] = {}
    for i in range(volume):
        at = T1 + VOLUME_STEP * (1 + (i * stride) % slots)
        batches.setdefault(at, []).extend(volume_records(i, at))
    return batches


def publisher(volume: int = 0):
    """Feed del día: el de `run_day` (tests/test_feed.py) más CVE_C (C) y CVE_B (C → B).

    Con `volume`, además esas CVE sintéticas (ver `volume_batches`), publicadas en orden de tiempo
    junto con las del montaje base.
    """
    engine, pub = make()
    batch1 = [
        vuln(CVE_EXPOSED),
        cve5_affected(CVE_EXPOSED),
        ssvc(CVE_EXPOSED),
        epss(CVE_EXPOSED, "2099-03-01", 0.42, T1),
        vuln(CVE_OTHER, product="example-left-pad"),
        ghsa_affected(CVE_OTHER),
        osv_affected(CVE_OTHER),
        vuln(CVE_RESTRICTED, product="Unlisted"),
        vulncheck(CVE_RESTRICTED, T1),
        vuln(CVE_C),
        cve5_affected(CVE_C),
        ssvc(CVE_C),
        vuln(CVE_B),
        cve5_affected(CVE_B),
        ssvc(CVE_B),
    ]
    batches = volume_batches(volume)
    for at, recs in (
        (T1, batch1),
        (T2, [msf(CVE_EXPOSED, T2), msf(CVE_B, T2)]),
        (T3, [kev(CVE_EXPOSED, T3)]),
    ):
        batches.setdefault(at, []).extend(recs)
    for at in sorted(batches):
        engine.ingest(batches[at], at)
        pub.publish_from_engine(engine, at)
    return pub


def metric_rows() -> list[MetricRow]:
    """Métricas sintéticas de 30 días hasta ayer (nombres propuestos en web/src/api/metrics.ts)."""
    rows: list[MetricRow] = []
    end = NOW.date() - timedelta(days=1)
    for i in range(30):
        d = end - timedelta(days=29 - i)
        ingested = 540 + (i * 37) % 120
        eligible = 60 + (i * 11) % 25
        candidate = 6 + i % 5
        rows += [
            MetricRow(d, "funnel.ingested", "", float(ingested)),
            MetricRow(d, "funnel.eligible", "", float(eligible)),
            MetricRow(d, "funnel.candidate", "", float(candidate)),
            MetricRow(d, "funnel.alerted", "A", float(i % 3 == 0)),
            MetricRow(d, "funnel.alerted", "B", float(i % 4 == 0)),
            MetricRow(d, "funnel.alerted", "C", float(1 + i % 2)),
            MetricRow(d, "detection.p50_minutes", "A", 35.0 + i % 7),
            MetricRow(d, "detection.p95_minutes", "A", 140.0 + i % 11),
            MetricRow(d, "detection.p50_minutes", "B", 48.0 + i % 9),
            MetricRow(d, "detection.p95_minutes", "B", 210.0 + i % 13),
            MetricRow(d, "detection.p50_minutes", "C", 22.0 + i % 5),
            MetricRow(d, "detection.p95_minutes", "C", 95.0 + i % 17),
            MetricRow(d, "changes.by_type", "new", float(ingested)),
            MetricRow(d, "changes.by_type", "level_up", float(i % 3)),
            MetricRow(d, "changes.by_type", "kev_added", float(i % 5 == 0)),
            MetricRow(d, "changes.by_type", "poc_added", float(1 + i % 3)),
            MetricRow(d, "changes.by_type", "fix_released", float(10 + i % 6)),
            MetricRow(d, "cost.eur", "azure", 2.4 + (i % 4) * 0.1),
            MetricRow(d, "cost.eur", "cloudflare", 0.2),
        ]
        if i % 6 == 0:
            rows.append(MetricRow(d, "kev_lead.p50_minutes", "", 600.0 + i * 40))
    return rows


def make_app(volume: int = 0):
    cfg = ApiConfig(
        instance=INSTANCE,
        publisher=publisher(volume),
        metrics=MemoryMetricsReader(metric_rows()),
        access=AccessVerifier(AccessConfig()),  # sin Access configurado: /admin cierra (403)
        donations_enabled=False,
        clock=lambda: NOW,
    )
    return create_app(cfg)


def handler(client: TestClient, static: Path | None):
    lock = threading.Lock()
    root = static.resolve() if static else None

    class Handler(BaseHTTPRequestHandler):
        server_version = "vs-portal-fixture"
        sys_version = ""

        def log_message(self, fmt, *args):  # silencio: la salida la lee Playwright
            return

        def _send(self, status: int, headers: dict[str, str], body: bytes) -> None:
            self.send_response(status)
            for k, v in headers.items():
                if k.lower() not in ("content-length", "transfer-encoding", "connection"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _api(self) -> None:
            fwd = {k: v for k, v in self.headers.items() if k.lower() not in ("host",)}
            with lock:
                resp = client.request(self.command, self.path, headers=fwd)
            headers = {k: v for k, v in resp.headers.items() if k.lower() != "content-encoding"}
            body = resp.content
            ctype = headers.get("content-type", "").split(";")[0].strip()
            if compressible(ctype) and "gzip" in self.headers.get("Accept-Encoding", ""):
                body = gzip.compress(body, compresslevel=6)
                headers["Content-Encoding"] = "gzip"
                headers["Vary"] = "Accept-Encoding"
            self._send(resp.status_code, headers, body)

        def _static(self) -> None:
            if root is None:
                self._send(404, {"Content-Type": "text/plain"}, b"sin build")
                return
            rel = self.path.split("?", 1)[0].lstrip("/") or "index.html"
            path = (root / rel).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                path = root / "index.html"  # SPA: cualquier ruta del portal sirve el índice
            ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            headers = {
                "Content-Type": ctype,
                "Cache-Control": "no-store",
                "Vary": "Accept-Encoding",
            }
            body = path.read_bytes()
            # Comprimido como lo sirve el borde en producción: si no, Lighthouse mide la red con el
            # JS sin comprimir (T8b).
            if compressible(ctype) and "gzip" in self.headers.get("Accept-Encoding", ""):
                body = gzip.compress(body, compresslevel=6)
                headers["Content-Encoding"] = "gzip"
            self._send(200, headers, body)

        def do_GET(self):  # noqa: N802 - nombre de BaseHTTPRequestHandler
            if is_api(self.path):
                self._api()
            else:
                self._static()

        do_HEAD = do_GET  # noqa: N815

        def _write(self):
            if is_api(self.path):
                self._api()
            else:
                self._send(405, {"Allow": "GET"}, b"")

        do_POST = do_PUT = do_PATCH = do_DELETE = _write  # noqa: N815

    return Handler


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--static", type=Path, default=None, help="build del portal (web/dist)")
    ap.add_argument(
        "--volume",
        type=int,
        default=0,
        help=f"CVE sintéticas extra en el día (capturas: {VOLUME_SHOTS}); 0 = montaje base",
    )
    args = ap.parse_args()
    client = TestClient(make_app(args.volume))
    server = ThreadingHTTPServer((args.host, args.port), handler(client, args.static))
    print(f"portal fixture en http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()


__all__ = [
    "NOW",
    "VOLUME_LEVELS",
    "VOLUME_SHOTS",
    "is_api",
    "make_app",
    "metric_rows",
    "publisher",
    "volume_batches",
    "volume_cve",
]
