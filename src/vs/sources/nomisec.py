"""PoC-in-GitHub de nomi-sec (SRC-011): repositorios de GitHub que dicen ser PoC de una CVE.

Licencia: `LICENSE` del repositorio (https://github.com/nomi-sec/PoC-in-GitHub, leído el
2026-11-26): «Creative Commons Legal Code / CC0 1.0 Universal». Clase `open`. El código de cada PoC
conserva la licencia de su autor: **se enlaza, no se aloja ni se clona** (ADR-0020 §6).

Lectura incremental sin clonar: la API de commits del repositorio da los commits posteriores al
cursor; cada commit lista los ficheros `AAAA/CVE-….json` que cambió; cada fichero se lee en su
versión de ese commit (`raw_base_url`). Solo se siguen enlaces bajo `api_url` y `raw_base_url`.
Fail-closed: si las páginas o los ficheros permitidos no llegan al cursor, UNKNOWN.

Cada repositorio da una señal `exploit` con `origin = github` (contrato de `vs.rules.exploit`). Las
heurísticas `poc_suspicious` (`vs.sources.poc`) se aplican con la API de GitHub a los repositorios
nuevos (creados después del cursor o en un fichero de CVE nuevo), con un presupuesto por ejecución.
Los demás quedan sin inspeccionar (`suspicious = None`) salvo lo que ya dicen sus metadatos (fork).
No se guarda la descripción del repositorio (texto de terceros, posible inyección: THR-001) ni las
estrellas (cambian cada hora y no deciden nada).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime, timedelta
from typing import Any

from vs.sources.base import Connector, LicenseClass, Record, is_cve_id, register
from vs.sources.github import github_headers
from vs.sources.http import SourceError, SourceIncomplete, get_ok, parse_json, parse_ts
from vs.sources.poc import (
    DEFAULT_BLOB_KB,
    PocInspector,
    PocVerdict,
    RepoFacts,
    evaluate,
)

DEFAULT_API_URL = "https://api.github.com/repos/nomi-sec/PoC-in-GitHub"
DEFAULT_RAW_BASE_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/"
DEFAULT_GITHUB_API = "https://api.github.com"
DEFAULT_MAX_PAGES = 3
DEFAULT_MAX_FILES = 2000
DEFAULT_MAX_FILE_PAGES = 10
DEFAULT_LOOKBACK_HOURS = 24
DEFAULT_MAX_INSPECTIONS = 30
GITHUB_HTML = "https://github.com/"

_PATH_RE = re.compile(r"^\d{4}/(CVE-\d{4}-\d{4,})\.json$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_NEXT_RE = re.compile(r'<([^>]+)>\s*;\s*rel="next"')
_FULL_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")


def next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    m = _NEXT_RE.search(link_header)
    return m.group(1) if m else None


def make_inspector(conn: Connector, *, on_request=None) -> PocInspector:
    cfg = conn.config
    return PocInspector(
        conn.transport,
        headers=github_headers(cfg),
        api_url=cfg.get("github_api_url", DEFAULT_GITHUB_API),
        max_inspections=int(cfg.get("max_inspections", DEFAULT_MAX_INSPECTIONS)),
        blob_kb=int(cfg.get("blob_kb", DEFAULT_BLOB_KB)),
        allowed_download_domains=tuple(cfg.get("allowed_download_domains") or ()),
        on_request=on_request,
    )


def repo_signal(
    conn: Connector,
    cve: str,
    item: Any,
    *,
    listed_by: str,
    inspector: PocInspector | None,
) -> Record:
    """Señal `exploit` (origin github) de un repositorio, con su veredicto `poc_suspicious`."""
    if not isinstance(item, Mapping):
        raise SourceError(f"{listed_by}: repositorio que no es un objeto ({cve})")
    full_name = item.get("full_name")
    owner = (
        (item.get("owner") or {}).get("login") if isinstance(item.get("owner"), Mapping) else None
    )
    html_url = item.get("html_url")
    if not isinstance(full_name, str) or not _FULL_NAME_RE.fullmatch(full_name):
        raise SourceError(f"{listed_by}: full_name no válido en {cve}: {full_name!r}")
    if not isinstance(owner, str) or full_name.split("/", 1)[0].lower() != owner.lower():
        raise SourceError(f"{listed_by}: dueño que no casa con {full_name!r} en {cve}")
    if html_url != GITHUB_HTML + full_name:
        raise SourceError(f"{listed_by}: html_url fuera de github.com en {full_name}")
    created = parse_ts(item.get("created_at"), f"{listed_by} {full_name} created_at")
    fork = item.get("fork")
    fork = bool(fork) if isinstance(fork, bool) else None

    if inspector is not None:
        verdict = inspector.inspect(full_name, owner=owner, fork=fork, repo_created_at=created)
    else:
        # Sin inspección: solo lo que dicen los metadatos (fork). Nunca «limpio».
        verdict = evaluate(RepoFacts(full_name=full_name, fork=fork, repo_created_at=created))
        if verdict.suspicious is False:  # pragma: no cover - sin hechos completos no ocurre
            verdict = PocVerdict(None)
    value = {
        "origin": "github",
        "owner": owner,
        "repo": full_name,
        "repo_id": item.get("id") if isinstance(item.get("id"), int) else None,
        "fork": fork,
        "created_at": created.isoformat(),
        "listed_by": listed_by,
        **verdict.to_value(),
    }
    return Record(
        source=conn.name,
        cve_id=cve,
        kind="exploit",
        license_class=conn.license_class,
        value=value,
        source_published_at=created,
        url=html_url,
    )


@register
class NomiSecConnector(Connector):
    name = "nomisec"
    license_class = LicenseClass.OPEN
    # El repositorio se actualiza varias veces al día (dos commits en seis horas el 2026-11-26).
    freshness_threshold = timedelta(hours=24)
    _headers: Mapping[str, str] = {}
    _inspector: PocInspector | None = None

    def _get_json(self, url: str, base: str) -> tuple[Any, str | None]:
        if not url.startswith(base):
            raise SourceError(f"PoC-in-GitHub: enlace fuera de {base}: {url}")
        resp = get_ok(self.transport, url, headers=self._headers)
        return parse_json(resp.body, url), resp.header("Link")

    def _commits(self, api: str) -> list[tuple[str, datetime]]:
        """Commits posteriores al cursor (o a la ventana de carga inicial), de más viejo a nuevo."""
        max_pages = int(self.config.get("max_pages", DEFAULT_MAX_PAGES))
        lookback = timedelta(
            hours=float(self.config.get("baseline_lookback_hours", DEFAULT_LOOKBACK_HOURS))
        )
        url: str | None = f"{api}/commits?per_page=100"
        out: list[tuple[str, datetime]] = []
        stop: datetime | None = self.since
        pages = 0
        while url is not None:
            if pages >= max_pages:
                raise SourceIncomplete(f"PoC-in-GitHub: {max_pages} páginas sin llegar al cursor")
            page, link = self._get_json(url, api)
            pages += 1
            if not isinstance(page, list):
                raise SourceError("PoC-in-GitHub: la lista de commits no es una lista")
            for c in page:
                sha = c.get("sha") if isinstance(c, dict) else None
                if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
                    raise SourceError(f"PoC-in-GitHub: sha no válido: {sha!r}")
                when = parse_ts(
                    ((c.get("commit") or {}).get("committer") or {}).get("date"),
                    f"PoC-in-GitHub commit {sha[:10]}",
                )
                if self.data_as_of is None:
                    self.data_as_of = when
                    if stop is None:
                        stop = when - lookback
                if stop is not None and when <= stop:
                    return list(reversed(out))
                out.append((sha, when))
            url = next_link(link)
        return list(reversed(out))

    def _changed_files(self, api: str, sha: str) -> list[tuple[str, str]]:
        """(ruta, estado) de los ficheros de un commit, con su paginación."""
        max_file_pages = int(self.config.get("max_file_pages", DEFAULT_MAX_FILE_PAGES))
        url: str | None = f"{api}/commits/{sha}"
        files: list[tuple[str, str]] = []
        pages = 0
        while url is not None:
            if pages >= max_file_pages:
                raise SourceIncomplete(f"PoC-in-GitHub: commit {sha[:10]} con demasiados ficheros")
            data, link = self._get_json(url, api)
            pages += 1
            if not isinstance(data, dict) or not isinstance(data.get("files"), list):
                raise SourceError(f"PoC-in-GitHub: commit {sha[:10]} sin 'files'")
            for f in data["files"]:
                if isinstance(f, dict) and isinstance(f.get("filename"), str):
                    files.append((f["filename"], str(f.get("status") or "")))
            url = next_link(link)
        return files

    def fetch(self) -> Iterator[dict[str, Any]]:
        api = self.config.get("api_url", DEFAULT_API_URL).rstrip("/")
        raw_base = self.config.get("raw_base_url", DEFAULT_RAW_BASE_URL)
        max_files = int(self.config.get("max_files", DEFAULT_MAX_FILES))
        self._headers = github_headers(self.config)
        inspect = bool(self.config.get("inspect", True))
        self._inspector = make_inspector(self) if inspect else None

        latest: dict[str, tuple[str, str, str]] = {}  # ruta → (sha, cve, estado)
        for sha, _when in self._commits(api):
            for path, status in self._changed_files(api, sha):
                m = _PATH_RE.match(path)
                if not m:
                    continue
                if status == "removed":
                    self.count("retirados")
                    latest.pop(path, None)
                    continue
                prev = latest.get(path)
                added = status == "added" or (prev is not None and prev[2] == "added")
                latest[path] = (sha, m.group(1), "added" if added else status)
        if len(latest) > max_files:
            raise SourceIncomplete(
                f"PoC-in-GitHub: {len(latest)} ficheros cambiados, más que el tope {max_files}"
            )
        for path, (sha, cve, status) in sorted(latest.items()):
            repos, _ = self._get_json(f"{raw_base}{sha}/{path}", raw_base)
            if not isinstance(repos, list):
                raise SourceError(f"PoC-in-GitHub: {path} no es una lista")
            yield {"cve": cve, "repos": repos, "status": status}
        if self._inspector is not None:
            for k, v in self._inspector.stats.items():
                self.count(f"inspeccion_{k}", v)

    def normalize(self, raw: dict[str, Any]) -> Iterable[Record]:
        cve = raw["cve"]
        if not is_cve_id(cve):  # pragma: no cover - la expresión de la ruta ya lo garantiza
            raise SourceError(f"PoC-in-GitHub: CVE no válida: {cve!r}")
        seen: set[str] = set()
        for item in raw["repos"]:
            name = item.get("full_name") if isinstance(item, dict) else None
            if name in seen:
                continue
            seen.add(name)
            created = item.get("created_at") if isinstance(item, dict) else None
            is_new = self.since is not None and (
                raw["status"] == "added"
                or (isinstance(created, str) and parse_ts(created, "created_at") > self.since)
            )
            yield repo_signal(
                self,
                cve,
                item,
                listed_by="nomi-sec",
                inspector=self._inspector if is_new else None,
            )
