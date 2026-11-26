"""OSV.dev (SRC-006): rangos por ecosistema, con licencia por fuente (ADR-0020).

OSV agrega bases con licencias distintas (https://google.github.io/osv.dev/data/, leído el
2026-11-26, tabla «Current data sources»). El conector decide por el prefijo del identificador:

- `excluded`: Chainguard/Wolfi («CC-BY-NC-ND 4.0 / Chainguard License for Commercial Scanners»).
  También se descarta cualquier `affected` de los ecosistemas Chainguard o Wolfi, venga de donde
  venga el registro.
- `share_alike`: Ubuntu («CC-BY-SA 4.0») y Alpine SecDB («CC-BY-SA 4.0»). Entran, marcados para la
  revisión legal.
- `open`: las fuentes de la tabla con CC0, CC-BY, MIT, BSD o Apache 2.0 cuyo prefijo se conoce.
- Cualquier otro prefijo (p. ej. Debian, o los CVE convertidos de NVD, para los que la página no da
  licencia) **no se lee**: se cuenta en `stats` y se salta. Añadir uno exige comprobar su licencia.

Lectura incremental con `modified_id.csv` («<iso modified date>,<ecosystem_dir>/<id>», del más
reciente al más antiguo). Se pide solo el principio del fichero (cabecera `Range`). Si la ventana
leída no llega al cursor, la ejecución es UNKNOWN (fail-closed).

Carga inicial: sin cursor, se leen solo los registros modificados en las últimas
`baseline_lookback_hours` (24 por defecto). La carga completa desde `all.zip` queda pendiente.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any
from urllib.parse import quote

from vs.sources.base import Connector, Entity, LicenseClass, Record, is_cve_id, register
from vs.sources.http import SourceError, SourceIncomplete, get_json, get_ok, parse_ts

DEFAULT_MODIFIED_URL = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
DEFAULT_RECORD_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com/"
OSV_VULN = "https://osv.dev/vulnerability/"
DEFAULT_HEAD_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_RECORDS = 5000
DEFAULT_LOOKBACK_HOURS = 24


class OsvPolicy(StrEnum):
    OPEN = "open"
    SHARE_ALIKE = "share_alike"
    EXCLUDED = "excluded"


# Prefijo del id → política. Fuente: tabla de https://google.github.io/osv.dev/data/ (2026-11-26).
PREFIX_POLICY: dict[str, OsvPolicy] = {
    "GHSA": OsvPolicy.OPEN,  # GitHub Advisory Database, CC-BY 4.0
    "PYSEC": OsvPolicy.OPEN,  # PyPI Advisory Database, CC-BY 4.0
    "GO": OsvPolicy.OPEN,  # Go Vulnerability Database, CC-BY 4.0
    "RUSTSEC": OsvPolicy.OPEN,  # Rust Advisory Database, CC0 1.0
    "OSV": OsvPolicy.OPEN,  # OSS-Fuzz, CC-BY 4.0
    "PSF": OsvPolicy.OPEN,  # Python Software Foundation Database, CC-BY 4.0
    "BIT": OsvPolicy.OPEN,  # Bitnami Vulnerability Database, Apache 2.0
    "MAL": OsvPolicy.OPEN,  # OpenSSF Malicious Packages, Apache 2.0
    "HSEC": OsvPolicy.OPEN,  # Haskell Security Advisories, CC0 1.0
    "RLSA": OsvPolicy.OPEN,  # Rocky Linux, BSD
    "RXSA": OsvPolicy.OPEN,  # Rocky Linux, BSD
    "ALSA": OsvPolicy.OPEN,  # AlmaLinux, MIT
    "ALBA": OsvPolicy.OPEN,  # AlmaLinux, MIT
    "ALEA": OsvPolicy.OPEN,  # AlmaLinux, MIT
    "RHSA": OsvPolicy.OPEN,  # Red Hat Security Data, CC-BY 4.0
    "RHBA": OsvPolicy.OPEN,  # Red Hat Security Data, CC-BY 4.0
    "RHEA": OsvPolicy.OPEN,  # Red Hat Security Data, CC-BY 4.0
    "CURL": OsvPolicy.OPEN,  # Curl, MIT
    "DHI": OsvPolicy.OPEN,  # Docker Hardened Images, Apache 2.0
    "UBUNTU": OsvPolicy.SHARE_ALIKE,  # Ubuntu, CC-BY-SA 4.0
    "USN": OsvPolicy.SHARE_ALIKE,  # Ubuntu, CC-BY-SA 4.0
    "LSN": OsvPolicy.SHARE_ALIKE,  # Ubuntu (Livepatch), CC-BY-SA 4.0
    "ALPINE": OsvPolicy.SHARE_ALIKE,  # Alpine SecDB, CC-BY-SA 4.0
    "CGA": OsvPolicy.EXCLUDED,  # Chainguard / Wolfi, CC-BY-NC-ND 4.0
}
EXCLUDED_ECOSYSTEMS = ("Chainguard", "Wolfi")


def policy_for(osv_id: str, ecosystem_dir: str = "") -> OsvPolicy | None:
    """Política del registro; None si su fuente no tiene licencia comprobada."""
    if ecosystem_dir.split(":", 1)[0] in EXCLUDED_ECOSYSTEMS:
        return OsvPolicy.EXCLUDED
    return PREFIX_POLICY.get(osv_id.split("-", 1)[0].upper())


def _excluded_ecosystem(ecosystem: str | None) -> bool:
    return bool(ecosystem) and ecosystem.split(":", 1)[0] in EXCLUDED_ECOSYSTEMS


@register
class OsvConnector(Connector):
    name = "osv"
    license_class = LicenseClass.OPEN
    # `modified_id.csv` cambia varias veces por hora.
    freshness_threshold = timedelta(hours=6)

    def _window(self) -> list[tuple[datetime, str, str]]:
        url = self.config.get("modified_url", DEFAULT_MODIFIED_URL)
        head = int(self.config.get("head_bytes", DEFAULT_HEAD_BYTES))
        resp = get_ok(
            self.transport, url, headers={"Range": f"bytes=0-{head - 1}"}, accept=(200, 206)
        )
        try:
            text = resp.body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SourceError(f"OSV: modified_id.csv no es UTF-8: {exc}") from exc
        truncated = resp.status == 206 or len(resp.body) >= head
        lines = text.split("\n")
        if truncated and lines:
            lines = lines[:-1]  # la última línea puede estar cortada
        out: list[tuple[datetime, str, str]] = []
        for line in lines:
            if not line.strip():
                continue
            ts_text, sep, path = line.strip().partition(",")
            eco, sep2, osv_id = path.rpartition("/")
            if not sep or not sep2 or not osv_id:
                raise SourceError(f"OSV: línea no válida en modified_id.csv: {line!r}")
            out.append((parse_ts(ts_text, "OSV modified"), eco, osv_id))
        if not out:
            raise SourceError("OSV: modified_id.csv vacío")
        if self.since is not None and truncated and min(t for t, _, _ in out) > self.since:
            raise SourceIncomplete(
                f"OSV: la ventana de {head} bytes no llega al cursor {self.since.isoformat()}"
            )
        return out

    def fetch(self) -> Iterator[dict[str, Any]]:
        base = self.config.get("record_base_url", DEFAULT_RECORD_BASE_URL)
        limit = int(self.config.get("max_records", DEFAULT_MAX_RECORDS))
        window = self._window()
        self.data_as_of = max(t for t, _, _ in window)
        since = self.since
        if since is None:  # carga inicial: solo la ventana reciente (ver docstring del módulo)
            hours = float(self.config.get("baseline_lookback_hours", DEFAULT_LOOKBACK_HOURS))
            since = self.data_as_of - timedelta(hours=hours)
        todo: list[tuple[str, str, OsvPolicy]] = []
        for ts, eco, osv_id in window:
            if ts <= since:
                continue
            policy = policy_for(osv_id, eco)
            if policy is None:
                self.count("sin_licencia_comprobada")
                continue
            if policy is OsvPolicy.EXCLUDED:
                self.count("excluidos")
                continue
            todo.append((eco, osv_id, policy))
        if len(todo) > limit:
            raise SourceError(f"OSV: {len(todo)} registros, más que max_records={limit}")
        for eco, osv_id, policy in todo:
            url = f"{base}{quote(eco)}/{quote(osv_id)}.json"
            rec = get_json(self.transport, url)
            if not isinstance(rec, dict) or rec.get("id") != osv_id:
                raise SourceError(f"OSV: {url} no contiene {osv_id}")
            yield {**rec, "_policy": policy}

    def normalize(self, raw: dict[str, Any]) -> Iterable[Record]:
        osv_id = raw.get("id") or ""
        policy = raw.get("_policy") or policy_for(osv_id)
        if policy is None or policy is OsvPolicy.EXCLUDED:
            # Defensa en profundidad: `fetch` ya no los lee.
            self.count("excluidos" if policy else "sin_licencia_comprobada")
            return
        aliases = [osv_id, *(raw.get("aliases") or [])]
        cves = sorted({a for a in aliases if is_cve_id(a)})
        if not cves:
            self.count("sin_cve")
            return
        published = parse_ts(raw.get("published") or raw.get("modified"), f"OSV {osv_id}")
        for a in raw.get("affected") or []:
            pkg = (a or {}).get("package") or {}
            if _excluded_ecosystem(pkg.get("ecosystem")):
                self.count("affected_excluidos")
                continue
            ranges = list(a.get("ranges") or [])
            if a.get("versions"):
                ranges.append({"type": "versions", "versions": list(a["versions"])})
            for cve in cves:
                yield Record(
                    source=self.name,
                    cve_id=cve,
                    kind="affected_product",
                    license_class=self.license_class,
                    entity=Entity.AFFECTED_PRODUCT,
                    value={
                        "vendor": None,
                        "product": pkg.get("name"),
                        "cpe": None,
                        "purl": pkg.get("purl"),
                        "ecosystem": pkg.get("ecosystem"),
                        "ranges": ranges,
                        "range_source": f"osv:{osv_id}",
                    },
                    source_published_at=published,
                    url=OSV_VULN + quote(osv_id),
                    share_alike=policy is OsvPolicy.SHARE_ALIKE,
                )
