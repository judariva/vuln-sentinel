"""Pata de despliegue desde Common Crawl: cabecera `Server` de una muestra fija de ficheros WAT.

Uso:
    uv run python -m vs.lists.deployment_cc --crawl CC-MAIN-2026-47 --output <encuesta.json>

Genera una encuesta normalizada en el formato de `vs.lists.deployment` (categoría `web-proxy`).

MÉTODO, fijado el 2026-11-26 ANTES de ejecutarlo con datos reales (R7). Cambiarlo exige subir
`METHOD_VERSION` y regenerar:
  1. Rastreo: el último de Common Crawl en la fecha de corte (se pasa con `--crawl`).
  2. Muestra: `SAMPLE_FILES` ficheros WAT repartidos a intervalos iguales en `wat.paths.gz`
     (índices i * total // SAMPLE_FILES) y, de cada uno, los primeros `PREFIX_BYTES` bytes
     (petición por rango; los WAT son gzip por miembros y se lee solo hasta el último completo).
     Los archivos de Common Crawl no cambian una vez publicados: la muestra es reproducible.
  3. Unidad: el host (de WARC-Target-URI, en minúsculas y sin «www.»). Cada host cuenta una vez,
     con el valor de `Server` de su primera respuesta en el orden de la muestra.
  4. Producto: primer término de `Server` en minúsculas, cortado en «/», espacio o «(»
     («Apache/2.4.58 (Ubuntu)» → apache, «Microsoft-IIS/10.0» → microsoft-iis).
  5. Clasificación con dos listas fijas (`INSTALLABLE` y `SERVICE`): solo entran en el ranking los
     servidores web o proxies que se instalan; los servicios y CDN («cloudflare») se excluyen; lo
     que no está en ninguna lista va a `needs_review`, nunca al ranking.
  6. `deployment.build` toma los N primeros del ranking por número de hosts.
Se guardan solo nombres y cuentas de hosts agregadas: ningún contenido rastreado.
"""

from __future__ import annotations

import argparse
import gzip
import json
import zlib
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path
from urllib.parse import urlsplit

from vs.lists.common import CACHE_DIR, fetch, sha256_bytes

METHOD_VERSION = 1
SAMPLE_FILES = 32
PREFIX_BYTES = 4 * 1024 * 1024
BASE_URL = "https://data.commoncrawl.org/"
TERMS_URL = "https://commoncrawl.org/terms-of-use"
LICENSE = "Common Crawl Terms of Use (2024-03-07): licencia limitada, no sublicenciable"
KEEP = 30  # nombres que se guardan por lista en la encuesta (transparencia; el ranking usa N)

# Servidores web y proxies inversos que se instalan (software propio o libre). Lista fijada antes
# de ver ningún resultado; un nombre nuevo se añade por PR con su motivo.
INSTALLABLE = frozenset(
    {
        "apache",
        "nginx",
        "openresty",
        "tengine",
        "litespeed",
        "openlitespeed",
        "microsoft-iis",
        "microsoft-httpapi",
        "caddy",
        "lighttpd",
        "envoy",
        "istio-envoy",
        "haproxy",
        "varnish",
        "traefik",
        "kestrel",
        "jetty",
        "apache-coyote",
        "tomcat",
        "gunicorn",
        "uvicorn",
        "werkzeug",
        "tornadoserver",
        "cherokee",
        "h2o",
        "hiawatha",
        "boa",
        "mini_httpd",
        "thttpd",
        "goahead",
        "goahead-webs",
        "webrick",
        "puma",
        "cowboy",
        "phusion_passenger",
        "zope",
        "resin",
        "glassfish",
        "wildfly",
        "undertow",
        "oracle-http-server",
        "ibm_http_server",
        "ats",
        "apachetrafficserver",
        "squid",
        "pound",
        "nghttpx",
        "mongoose",
        "civetweb",
        "yaws",
        "akka-http",
        "lotus-domino",
        "embedthis-appweb",
        "abyss",
        "zeus",
    }
)

# Servicios alojados y CDN: la cabecera nombra al proveedor, no un software que se instala.
SERVICE = frozenset(
    {
        "cloudflare",
        "gws",
        "gse",
        "esf",
        "sffe",
        "google",
        "akamaighost",
        "akamainetstorage",
        "amazons3",
        "awselb",
        "cloudfront",
        "vercel",
        "netlify",
        "github.com",
        "ecacc",
        "ecs",
        "ecd",
        "pepyaka",
        "squarespace",
        "shopify",
        "bunnycdn",
        "cdn77-turbo",
        "keycdn-engine",
        "sucuri",
        "ddos-guard",
        "qrator",
        "myracloud",
        "fastly",
        "windows-azure-blob",
        "windows-azure-web",
        "microsoft-azure-application-gateway",
        "aliyunoss",
        "dps",
        "wix",
        "wordpress.com",
        "medium",
        "tumblr",
        "blogger",
        "wpengine",
        "kinsta",
        "flywheel",
        "pantheon",
        "heroku",
        "fly",
        "railway",
        "render",
    }
)


def product_of(server: str) -> str:
    """Paso 4: primer término de la cabecera `Server`, en minúsculas."""
    s = server.strip().lower()
    for sep in ("/", " ", "("):
        s = s.split(sep, 1)[0]
    return s.strip()


def host_of(uri: str) -> str:
    host = (urlsplit(uri).hostname or "").lower()
    return host.removeprefix("www.")


def sample_paths(paths: list[str], k: int = SAMPLE_FILES) -> list[str]:
    """Paso 2: `k` rutas a intervalos iguales."""
    n = len(paths)
    if n <= k:
        return list(paths)
    return [paths[i * n // k] for i in range(k)]


def iter_members(data: bytes) -> Iterator[bytes]:
    """Miembros gzip completos de un prefijo de fichero (descarta el último si está cortado)."""
    pos = 0
    while pos < len(data):
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            out = d.decompress(data[pos:])
        except zlib.error:
            return
        if not d.eof:
            return
        yield out
        pos = len(data) - len(d.unused_data)


def responses(members: Iterable[bytes]) -> Iterator[tuple[str, str]]:
    """(host, Server) de cada registro de metadatos de una respuesta HTTP con cabecera Server."""
    for raw in members:
        body = raw.decode("utf-8", "replace").split("\r\n\r\n", 1)[-1].strip()
        if not body.startswith("{"):
            continue
        try:
            env = json.loads(body).get("Envelope", {})
        except json.JSONDecodeError:
            continue
        meta = (env.get("Payload-Metadata") or {}).get("HTTP-Response-Metadata") or {}
        headers = {k.lower(): v for k, v in (meta.get("Headers") or {}).items()}
        uri = (env.get("WARC-Header-Metadata") or {}).get("WARC-Target-URI", "")
        server = headers.get("server")
        if isinstance(server, list):
            server = server[0] if server else ""
        if uri and server:
            yield host_of(uri), str(server)


def survey(prefixes: list[bytes], crawl: str, files: list[str]) -> dict:
    """Pasos 3–5: encuesta normalizada a partir de los prefijos WAT, en el orden de la muestra."""
    first: dict[str, str] = {}
    for data in prefixes:
        for host, server in responses(iter_members(data)):
            if host and host not in first:
                first[host] = product_of(server)
    counts = Counter(p for p in first.values() if p)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    keep = {
        "ranking": [(n, c) for n, c in ranked if n in INSTALLABLE],
        "excluded": [(n, c) for n, c in ranked if n in SERVICE],
        "needs_review": [(n, c) for n, c in ranked if n not in INSTALLABLE | SERVICE],
    }
    total = len(first)
    return {
        "source": f"Common Crawl {crawl}, cabecera Server de una muestra de WAT",
        "url": f"{BASE_URL}crawl-data/{crawl}/wat.paths.gz",
        "license": LICENSE,
        "terms_url": TERMS_URL,
        "survey_date": None,  # lo rellena main() con la fecha de corte
        "category": "web-proxy",
        "method": {
            "version": METHOD_VERSION,
            "crawl": crawl,
            "sample_files": len(files),
            "prefix_bytes": PREFIX_BYTES,
            "unit": "host",
            "files": files,
            "inputs_sha256": sha256_bytes(b"".join(sha256_bytes(p).encode() for p in prefixes)),
        },
        "hosts": total,
        **{
            key: [{"name": n, "share": round(c / total, 6), "hosts": c} for n, c in items[:KEEP]]
            for key, items in keep.items()
        },
    }


def _fetch_range(url: str, nbytes: int, target: Path, attempts: int = 8) -> bytes:
    """Primeros `nbytes` de `url`, con caché. Reintenta 503/429 (límite de tasa de Common Crawl)."""
    import time
    import urllib.error
    import urllib.request

    if target.exists():
        return target.read_bytes()
    if not url.startswith("https://"):
        raise ValueError(url)
    req = urllib.request.Request(  # noqa: S310 (solo https, comprobado arriba)
        url, headers={"User-Agent": "vuln-sentinel-lists", "Range": f"bytes=0-{nbytes - 1}"}
    )
    for i in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310
                data = resp.read()
            break
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 503) or i == attempts - 1:
                raise
            time.sleep(min(60, 2 ** (i + 1)))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return data


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--crawl", required=True)
    ap.add_argument("--cutoff", required=True, help="fecha de corte (YYYY-MM-DD)")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    cache = CACHE_DIR / "commoncrawl" / args.crawl
    paths_gz = fetch(f"{BASE_URL}crawl-data/{args.crawl}/wat.paths.gz", "wat.paths.gz", cache)
    files = sample_paths(gzip.decompress(paths_gz).decode().split())
    prefixes = [
        _fetch_range(BASE_URL + f, PREFIX_BYTES, cache / "wat" / Path(f).name) for f in files
    ]
    doc = survey(prefixes, args.crawl, files)
    doc["survey_date"] = args.cutoff
    args.output.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{args.output}: {doc['hosts']} hosts, {[r['name'] for r in doc['ranking'][:5]]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
