"""cvelistV5 (SRC-001): CVE nuevas y cambiadas, con el ADP de CISA (SSVC).

Licencia (CVE Program Terms of Use, https://www.cve.org/Legal/TermsOfUse; texto leído el
2026-11-26 en su fuente, https://github.com/CVEProject/cve-website,
`src/views/Legal/TermsOfUse.vue`, porque la página es una SPA): «MITRE hereby grants you a
perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to
reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and
distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for such purposes is
authorized provided that you reproduce MITRE's copyright designation and this license in any such
copy.» Clase `open`; el aviso de MITRE se reproduce en el feed (`NOTICE`).

Lectura incremental con `cves/deltaLog.json` (el repo se actualiza «about every 7 minutes»): cada
entrada trae `fetchTime` y las CVE nuevas y actualizadas con su `githubLink`. Solo se siguen
enlaces bajo `record_base_url`: el dato de la fuente no decide a qué host se conecta el monitor.

Carga inicial: sin cursor, se leen solo las entradas del `deltaLog` de las últimas
`baseline_lookback_hours` (24 por defecto). La carga completa (el zip diario de todas las CVE)
queda pendiente.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta
from typing import Any

from vs.sources.base import Connector, Entity, LicenseClass, Record, is_cve_id, register
from vs.sources.http import SourceError, SourceIncomplete, get_json, parse_ts

DEFAULT_DELTA_LOG_URL = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
)
DEFAULT_RECORD_BASE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
CVE_ORG = "https://www.cve.org/CVERecord?id="
DEFAULT_MAX_RECORDS = 20000  # pico medido: ~8.500 cambios en un día (ADR-0019)
DEFAULT_LOOKBACK_HOURS = 24

# Preferencia de métricas: la versión más reciente de CVSS.
CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
RANGE_KEYS = ("version", "lessThan", "lessThanOrEqual", "status", "versionType", "changes")


def _cvss(metrics: Any) -> str | None:
    if not isinstance(metrics, list):
        return None
    for key in CVSS_KEYS:
        for m in metrics:
            if isinstance(m, dict) and isinstance(m.get(key), dict):
                vector = m[key].get("vectorString")
                if vector:
                    return vector
    return None


def _cwes(container: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for pt in container.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            cwe = d.get("cweId")
            if isinstance(cwe, str) and cwe.startswith("CWE-") and cwe not in out:
                out.append(cwe)
    return out


def _ssvc(adp: dict[str, Any]) -> tuple[dict[str, Any], str] | None:
    for m in adp.get("metrics") or []:
        other = m.get("other") if isinstance(m, dict) else None
        if isinstance(other, dict) and other.get("type") == "ssvc":
            content = other.get("content") or {}
            opts: dict[str, str] = {}
            for o in content.get("options") or []:
                if isinstance(o, dict):
                    opts.update({str(k): str(v) for k, v in o.items()})
            value = {
                "exploitation": opts.get("Exploitation", "").lower() or None,
                "automatable": opts.get("Automatable", "").lower() or None,
                "technical_impact": opts.get("Technical Impact", "").lower() or None,
                "version": content.get("version"),
                "role": content.get("role"),
            }
            return value, content.get("timestamp")
    return None


@register
class CveListV5Connector(Connector):
    name = "cvelistv5"
    license_class = LicenseClass.OPEN
    # El deltaLog se regenera cada pocos minutos; dos horas sin cambios es una avería.
    freshness_threshold = timedelta(hours=2)

    def fetch(self) -> Iterator[dict[str, Any]]:
        log_url = self.config.get("delta_log_url", DEFAULT_DELTA_LOG_URL)
        base = self.config.get("record_base_url", DEFAULT_RECORD_BASE_URL)
        limit = int(self.config.get("max_records", DEFAULT_MAX_RECORDS))
        log = get_json(self.transport, log_url)
        if not isinstance(log, list) or not log:
            raise SourceError("cvelistV5: deltaLog vacío o sin formato de lista")
        deltas: list[tuple[datetime, dict[str, Any]]] = []
        for d in log:
            if not isinstance(d, dict):
                raise SourceError("cvelistV5: entrada de deltaLog que no es un objeto")
            deltas.append((parse_ts(d.get("fetchTime"), "deltaLog fetchTime"), d))
        self.data_as_of = max(t for t, _ in deltas)
        since = self.since
        if since is None:  # carga inicial: solo la ventana reciente (ver docstring del módulo)
            hours = float(self.config.get("baseline_lookback_hours", DEFAULT_LOOKBACK_HOURS))
            since = self.data_as_of - timedelta(hours=hours)
        elif min(t for t, _ in deltas) > since:
            raise SourceIncomplete(f"cvelistV5: el deltaLog no llega al cursor {since.isoformat()}")
        # La entrada más reciente gana: un registro actualizado dos veces se lee una sola.
        links: dict[str, str] = {}
        for t, d in sorted(deltas, key=lambda x: x[0]):
            if t <= since:
                continue
            for item in [*(d.get("new") or []), *(d.get("updated") or [])]:
                cve, link = item.get("cveId"), item.get("githubLink")
                if not is_cve_id(cve):
                    raise SourceError(f"cvelistV5: cveId no válido: {cve!r}")
                if not isinstance(link, str) or not link.startswith(base):
                    raise SourceError(f"cvelistV5: enlace fuera de {base}: {link!r}")
                links[cve] = link
        if len(links) > limit:
            raise SourceError(f"cvelistV5: {len(links)} registros, más que max_records={limit}")
        for cve, link in sorted(links.items()):
            rec = get_json(self.transport, link)
            got = (rec.get("cveMetadata") or {}).get("cveId") if isinstance(rec, dict) else None
            if got != cve:
                raise SourceError(f"cvelistV5: {link} no contiene {cve} (trae {got!r})")
            yield rec

    def normalize(self, raw: dict[str, Any]) -> Iterable[Record]:
        meta = raw.get("cveMetadata") or {}
        cve = meta.get("cveId")
        if not is_cve_id(cve):
            raise SourceError(f"cvelistV5: cveId no válido: {cve!r}")
        state = meta.get("state")
        cna = (raw.get("containers") or {}).get("cna") or {}
        adps = [a for a in (raw.get("containers") or {}).get("adp") or [] if isinstance(a, dict)]
        url = CVE_ORG + cve

        if state == "REJECTED":
            when = meta.get("dateRejected") or meta.get("dateUpdated")
            ts = parse_ts(when, f"{cve} dateRejected")
            published = parse_ts(meta.get("datePublished") or when, f"{cve} datePublished")
            yield self._vuln(cve, published, {"cna": meta.get("assignerShortName")}, ts)
            return
        if state != "PUBLISHED":
            raise SourceError(f"cvelistV5: estado desconocido en {cve}: {state!r}")

        published = parse_ts(meta.get("datePublished"), f"{cve} datePublished")
        affected = [a for a in cna.get("affected") or [] if isinstance(a, dict)]
        cvss, cvss_source = _cvss(cna.get("metrics")), "cna"
        if cvss is None:
            for adp in adps:
                cvss = _cvss(adp.get("metrics"))
                if cvss:
                    cvss_source = (adp.get("providerMetadata") or {}).get("shortName") or "adp"
                    break
        cwes = _cwes(cna)
        for adp in adps:
            cwes += [c for c in _cwes(adp) if c not in cwes]
        first = affected[0] if affected else {}
        yield self._vuln(
            cve,
            published,
            {
                "cna": meta.get("assignerShortName"),
                "cvss_vector": cvss,
                "cvss_source": cvss_source if cvss else None,
                "cwe": cwes,
                "vendor": first.get("vendor"),
                "product": first.get("product") or first.get("packageName"),
            },
            None,
        )

        cna_updated = (cna.get("providerMetadata") or {}).get("dateUpdated")
        range_published = (
            parse_ts(cna_updated, f"{cve} cna.dateUpdated") if cna_updated else published
        )
        for a in affected:
            ranges = [
                {k: v for k, v in ver.items() if k in RANGE_KEYS}
                for ver in a.get("versions") or []
                if isinstance(ver, dict)
            ]
            cpes = a.get("cpes") or []
            yield Record(
                source=self.name,
                cve_id=cve,
                kind="affected_product",
                license_class=self.license_class,
                entity=Entity.AFFECTED_PRODUCT,
                value={
                    "vendor": a.get("vendor"),
                    "product": a.get("product") or a.get("packageName"),
                    "cpe": cpes[0] if cpes else None,
                    "purl": a.get("packageURL"),
                    "ecosystem": a.get("collectionURL"),
                    "ranges": [
                        {
                            "type": "cve5",
                            "default_status": a.get("defaultStatus"),
                            "versions": ranges,
                        }
                    ],
                    "range_source": f"cna:{meta.get('assignerShortName')}",
                },
                source_published_at=range_published,
                url=url,
            )

        for adp in adps:
            found = _ssvc(adp)
            if found is None:
                continue
            value, ts = found
            yield Record(
                source=self.name,
                cve_id=cve,
                kind="ssvc",
                license_class=self.license_class,
                entity=Entity.SIGNAL,
                value={**value, "provider": (adp.get("providerMetadata") or {}).get("shortName")},
                source_published_at=parse_ts(ts, f"{cve} SSVC timestamp") if ts else None,
                url=url,
            )

    def _vuln(
        self,
        cve: str,
        published: datetime,
        cols: dict[str, Any],
        withdrawn_at: datetime | None,
    ) -> Record:
        return Record(
            source=self.name,
            cve_id=cve,
            kind="vulnerability",
            license_class=self.license_class,
            entity=Entity.VULNERABILITY,
            value={**cols, "withdrawn_at": withdrawn_at},
            source_published_at=published,
            url=CVE_ORG + cve,
        )
