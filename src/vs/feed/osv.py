"""Registro OSV 1.9 extendido, uno por CVE (PLAN.md §3, ADR-0007, ADR-0019).

Un cliente que solo entienda OSV cruza por `affected[].package` (ecosistema, nombre, purl) y
`ranges`, sin leer la extensión. Lo propio de vuln-sentinel va en `database_specific.vuln_sentinel`
(raíz) y en el `database_specific` de cada `affected[]`.

Reglas de construcción (deterministas; las prueba `tests/test_feed.py`):

- `id = VS-<CVE>`: estable, uno por CVE, nunca se reutiliza.
- Solo se usan los registros que la audiencia del feed puede recibir; el filtro lo hace quien
  llama (`vs.feed.publish`), y aquí se vuelve a comprobar que todos son de la misma CVE.
- `affected[].package` solo se rellena con un ecosistema OSV válido (de OSV, de GHSA o del tipo del
  purl). Sin ecosistema, el producto va solo en `database_specific` (OSV 1.9.2 no admite
  «Generic»).
- Los rangos de OSV pasan tal cual. Los de CVE 5 y GHSA se convierten a eventos cuando la
  conversión es exacta; si no, el rango original va en `database_specific.raw_ranges`.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any

from vs.feed.config import OSV_SCHEMA_VERSION
from vs.rules.engine import LevelChange
from vs.rules.exploit import EXPLOIT_KIND, exploit_rules, poc_status
from vs.rules.levels import Level
from vs.rules.lists import EMPTY_LISTS, RuleLists
from vs.sources.base import Entity, Record, is_cve_id

ID_PREFIX = "VS-"
ID_RE = re.compile(r"VS-CVE-\d{4}-\d{4,}")

# Tipos de cambio (PLAN.md §3). `updated` cubre cualquier otro cambio del registro (pregunta
# abierta en el informe de T5). El orden es la prioridad del tipo que va al índice.
CHANGE_TYPES = (
    "new",
    "withdrawn",
    "level_up",
    "kev_added",
    "poc_added",
    "fix_released",
    "range_completed",
    "epss_jump",
    "updated",
)

# Ecosistemas de la base de datos de avisos de GitHub → nombre OSV (OSV 1.9.2, `ecosystemName`).
GHSA_ECOSYSTEMS: Mapping[str, str] = {
    "actions": "GitHub Actions",
    "composer": "Packagist",
    "erlang": "Hex",
    "go": "Go",
    "maven": "Maven",
    "npm": "npm",
    "nuget": "NuGet",
    "pip": "PyPI",
    "pub": "Pub",
    "rubygems": "RubyGems",
    "rust": "crates.io",
    "swift": "SwiftURL",
}

# Tipo de purl → ecosistema OSV, solo los inequívocos.
PURL_ECOSYSTEMS: Mapping[str, str] = {
    "cargo": "crates.io",
    "composer": "Packagist",
    "gem": "RubyGems",
    "golang": "Go",
    "hex": "Hex",
    "maven": "Maven",
    "npm": "npm",
    "nuget": "NuGet",
    "pub": "Pub",
    "pypi": "PyPI",
}

_OSV_RANGE_TYPES = frozenset({"SEMVER", "ECOSYSTEM", "GIT"})
_GHSA_CMP_RE = re.compile(r"^(>=|<=|<|>|=)\s*(\S+)$")


def alert_id(cve_id: str) -> str:
    """`VS-CVE-AAAA-NNNN`: estable para siempre."""
    if not is_cve_id(cve_id):
        raise ValueError(f"no es un identificador CVE: {cve_id!r}")
    return ID_PREFIX + cve_id


def ts(value: datetime | None) -> str | None:
    """Marca de tiempo RFC 3339 en UTC con `Z` (patrón `timestamp` de OSV)."""
    if value is None:
        return None
    if value.tzinfo is None:
        raise ValueError("marca de tiempo sin zona horaria")
    value = value.astimezone(UTC)
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ" if value.microsecond else "%Y-%m-%dT%H:%M:%SZ"
    return value.strftime(fmt)


def _ts_any(value: Any) -> str | None:
    if isinstance(value, datetime):
        return ts(value)
    if isinstance(value, date):
        return value.isoformat()
    return None if value is None else str(value)


def canonical_bytes(doc: Any) -> bytes:
    """Bytes exactos que se publican, se resumen y se firman."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# -- severidad ------------------------------------------------------------------------------------


def osv_severity(vector: str | None, cvss_source: str | None) -> list[dict[str, str]]:
    if not vector:
        return []
    if vector.startswith("CVSS:4.0/"):
        kind = "CVSS_V4"
    elif vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        kind = "CVSS_V3"
    elif vector.startswith("AV:"):
        kind = "CVSS_V2"
    else:
        return []
    item = {"type": kind, "score": vector}
    if (cvss_source or "").lower() == "cna":
        item["source"] = "CNA"
    return [item]


# -- productos y rangos ---------------------------------------------------------------------------


def osv_ecosystem(rec: Record) -> str | None:
    """Ecosistema OSV del producto, o None si no hay uno inequívoco."""
    v = rec.value
    eco = v.get("ecosystem")
    if rec.source == "osv" and isinstance(eco, str) and eco:
        return eco
    if rec.source == "ghsa" and isinstance(eco, str):
        return GHSA_ECOSYSTEMS.get(eco.lower())
    purl = v.get("purl")
    if isinstance(purl, str) and purl.startswith("pkg:"):
        ptype = purl[4:].split("/", 1)[0].lower()
        return PURL_ECOSYSTEMS.get(ptype)
    return None


def _cve5_ranges(rng: Mapping[str, Any]) -> tuple[list[dict], list[str], bool]:
    """Rango de CVE 5 → (rangos OSV, versiones sueltas, ¿exacto?)."""
    fixed: dict[str, list[dict]] = {}
    last: dict[str, list[dict]] = {}
    versions: list[str] = []
    # Cualquier entrada que no sea un rango «affected» convertible (p. ej. «unaffected», que
    # matiza el rango) hace la conversión inexacta: el original se conserva en `raw_ranges`.
    exact = True
    for ver in rng.get("versions") or []:
        if not isinstance(ver, Mapping) or ver.get("status") != "affected":
            exact = False
            continue
        start = str(ver.get("version") or "")
        if start in ("", "*", "n/a", "unspecified"):
            start = "0"
        rtype = "SEMVER" if str(ver.get("versionType") or "").lower() == "semver" else "ECOSYSTEM"
        lt, lte = ver.get("lessThan"), ver.get("lessThanOrEqual")
        if lt not in (None, "", "*"):
            fixed.setdefault(rtype, []).extend([{"introduced": start}, {"fixed": str(lt)}])
        elif lte not in (None, "", "*"):
            last.setdefault(rtype, []).extend([{"introduced": start}, {"last_affected": str(lte)}])
        elif "*" in (lt, lte):
            fixed.setdefault(rtype, []).append({"introduced": start})
        elif start != "0":
            versions.append(start)
        else:
            exact = False
    out = [{"type": t, "events": ev} for t, ev in sorted(fixed.items())]
    out += [{"type": t, "events": ev} for t, ev in sorted(last.items())]
    return out, versions, exact


def _ghsa_ranges(rng: Mapping[str, Any]) -> tuple[list[dict], list[str], bool]:
    """`vulnerable_version_range` de GHSA (p. ej. `>= 1.0, < 1.4.2`) → eventos ECOSYSTEM."""
    text = str(rng.get("vulnerable_version_range") or "").strip()
    if not text:
        return [], [], False
    introduced = "0"
    upper: dict[str, str] = {}
    for part in (p.strip() for p in text.split(",")):
        m = _GHSA_CMP_RE.match(part)
        if not m:
            return [], [], False
        op, ver = m.groups()
        if op == ">=":
            introduced = ver
        elif op == "<":
            upper = {"fixed": ver}
        elif op == "<=":
            upper = {"last_affected": ver}
        elif op == "=":
            return [], [ver], True
        else:  # «>» no se puede expresar con `introduced` (inclusivo)
            return [], [], False
    patched = rng.get("first_patched_version")
    if not upper and patched:
        upper = {"fixed": str(patched)}
    events = [{"introduced": introduced}, *([upper] if upper else [])]
    return [{"type": "ECOSYSTEM", "events": events}], [], True


def _osv_range(rng: Mapping[str, Any]) -> dict | None:
    if rng.get("type") not in _OSV_RANGE_TYPES or not rng.get("events"):
        return None
    out = {"type": rng["type"], "events": [dict(e) for e in rng["events"]]}
    if rng.get("repo"):
        out["repo"] = rng["repo"]
    return out


def convert_ranges(ranges: Sequence[Mapping[str, Any]]) -> tuple[list[dict], list[str], list]:
    """Rangos normalizados por los conectores → (rangos OSV, versiones, rangos sin convertir)."""
    osv: list[dict] = []
    versions: list[str] = []
    raw: list = []
    for rng in ranges or []:
        if not isinstance(rng, Mapping):
            raw.append(rng)
            continue
        kind = rng.get("type")
        if kind == "versions":
            versions += [str(v) for v in rng.get("versions") or []]
            continue
        if kind == "cve5":
            got, vers, exact = _cve5_ranges(rng)
        elif kind == "ghsa":
            got, vers, exact = _ghsa_ranges(rng)
        else:
            one = _osv_range(rng)
            got, vers, exact = ([one], [], True) if one else ([], [], False)
        osv += got
        versions += vers
        if not exact:
            raw.append(dict(rng))
    return osv, versions, raw


def _affected(rec: Record) -> dict[str, Any]:
    v = rec.value
    ranges, versions, raw = convert_ranges(v.get("ranges") or [])
    item: dict[str, Any] = {}
    eco = osv_ecosystem(rec)
    name = v.get("product")
    if eco and name:
        pkg = {"ecosystem": eco, "name": str(name)}
        if v.get("purl"):
            pkg["purl"] = str(v["purl"])
        item["package"] = pkg
    if ranges:
        item["ranges"] = ranges
    if versions:
        item["versions"] = sorted(set(versions))
    ds: dict[str, Any] = {"source": rec.source, "range_source": v.get("range_source")}
    for key in ("vendor", "product"):
        if v.get(key):
            ds[key] = v[key]
    cpe = v.get("cpe")
    if cpe:
        ds["cpe"] = list(cpe) if isinstance(cpe, list | tuple) else [cpe]
    if v.get("purl") and "package" not in item:
        ds["purl"] = v["purl"]
    if raw:
        ds["raw_ranges"] = raw
    item["database_specific"] = ds
    return item


def _fixed_versions(affected: Iterable[Mapping[str, Any]]) -> list[str]:
    out = set()
    for a in affected:
        for r in a.get("ranges") or []:
            out |= {e["fixed"] for e in r["events"] if "fixed" in e}
    return sorted(out)


# -- señales --------------------------------------------------------------------------------------


def _latest(records: Iterable[Record]) -> Record | None:
    best = None
    for r in records:
        key = (r.source_published_at or r.observed_at, r.observed_at)
        if best is None or key >= (best.source_published_at or best.observed_at, best.observed_at):
            best = r
    return best


def _epss(epss: list[Record]) -> dict[str, Any] | None:
    if not epss:
        return None

    def day(r: Record) -> str:
        return str(r.value.get("score_date") or "")

    epss = sorted(epss, key=lambda r: (day(r), r.observed_at))
    last = epss[-1]
    out: dict[str, Any] = {
        "score": last.value.get("epss"),
        "percentile": last.value.get("percentile"),
        "model": last.value.get("model_version"),
        "date": day(last),
        "delta_7d": None,
    }
    try:
        cut = (date.fromisoformat(day(last)) - timedelta(days=7)).isoformat()
    except ValueError:
        return out
    older = [r for r in epss if day(r) and day(r) <= cut]
    if older and isinstance(last.value.get("epss"), int | float):
        prev = older[-1].value.get("epss")
        if isinstance(prev, int | float):
            out["delta_7d"] = round(float(last.value["epss"]) - float(prev), 6)
    return out


def _signals(signals: list[Record], lists: RuleLists) -> dict[str, Any]:
    by_kind: dict[str, list[Record]] = {}
    for s in signals:
        by_kind.setdefault(s.kind, []).append(s)

    kev = by_kind.get("kev_cisa", [])
    first_kev = min((r.observed_at for r in kev if r.observed_at), default=None)
    out: dict[str, Any] = {
        "kev": {
            "cisa": bool(kev),
            "date_added": kev[0].value.get("date_added") if kev else None,
            "observed_at": ts(first_kev),
        }
    }
    ssvc = _latest(by_kind.get("ssvc", []))
    if ssvc is not None:
        out["ssvc"] = {
            "exploitation": ssvc.value.get("exploitation"),
            "automatable": ssvc.value.get("automatable"),
            "technical_impact": ssvc.value.get("technical_impact"),
            "source_published_at": ts(ssvc.source_published_at),
            "observed_at": ts(ssvc.observed_at),
        }
    epss = _epss(by_kind.get("epss", []))
    if epss is not None:
        out["epss"] = epss
    exploits = []
    for s in by_kind.get(EXPLOIT_KIND, []):
        rules = exploit_rules([s.value], None, lists)
        exploits.append(
            {
                "rule": rules[0].value if rules else None,
                "status": poc_status(s.value, lists),
                "origin": s.value.get("origin"),
                "url": s.url,
                "source_published_at": ts(s.source_published_at),
                "observed_at": ts(s.observed_at),
            }
        )
    out["exploits"] = sorted(exploits, key=lambda e: (e["observed_at"] or "", e["url"] or ""))
    vendor = by_kind.get("vendor_exploited", [])
    if vendor:
        out["vendor_exploited"] = [
            {"url": s.url, "observed_at": ts(s.observed_at)}
            for s in sorted(vendor, key=lambda s: s.url or "")
        ]
    return out


def _references(records: Iterable[Record]) -> list[dict[str, str]]:
    seen: dict[str, str] = {}
    for r in records:
        if not r.url or not r.url.startswith(("https://", "http://")):
            continue
        kind = "ADVISORY" if r.entity is not Entity.SIGNAL else "WEB"
        if seen.get(r.url) != "ADVISORY":
            seen[r.url] = kind
    return [{"type": t, "url": u} for u, t in sorted(seen.items())]


def _sources(records: Iterable[Record]) -> list[dict[str, Any]]:
    acc: dict[str, dict[str, Any]] = {}
    for r in sorted(records, key=lambda r: (r.observed_at, r.url or "")):
        cur = acc.setdefault(
            r.source,
            {"name": r.source, "url": r.url, "source_published_at": None, "observed_at": None},
        )
        cur["url"] = cur["url"] or r.url
        if r.source_published_at and (
            cur["source_published_at"] is None or r.source_published_at < cur["source_published_at"]
        ):
            cur["source_published_at"] = r.source_published_at
        if r.observed_at and (cur["observed_at"] is None or r.observed_at < cur["observed_at"]):
            cur["observed_at"] = r.observed_at
    return [
        {
            **s,
            "source_published_at": ts(s["source_published_at"]),
            "observed_at": ts(s["observed_at"]),
        }
        for _, s in sorted(acc.items())
    ]


def _aliases(cve_id: str, records: Iterable[Record]) -> list[str]:
    out = {cve_id}
    for r in records:
        rs = str(r.value.get("range_source") or "") if r.entity is Entity.AFFECTED_PRODUCT else ""
        prefix, _, ident = rs.partition(":")
        if prefix in ("ghsa", "osv") and ident and ident != cve_id:
            out.add(ident)
    return [cve_id, *sorted(out - {cve_id})]


def level_history(changes: Iterable[LevelChange]) -> list[dict[str, Any]]:
    return [
        {
            "level": c.level_to.label,
            "from": c.level_from.label,
            "at": ts(c.at),
            "reason": list(c.reason),
            "decided_by": c.decided_by,
        }
        for c in changes
    ]


# -- registro -------------------------------------------------------------------------------------


def build_record(
    cve_id: str,
    records: Iterable[Record],
    *,
    level: Level,
    level_reason: Sequence[str],
    impact_class: str,
    history: Iterable[LevelChange],
    changes: Sequence[Mapping[str, Any]],
    published: datetime,
    modified: datetime,
    lists: RuleLists = EMPTY_LISTS,
) -> dict[str, Any]:
    """Registro OSV de una CVE con su extensión. No filtra por derechos: lo hace quien llama."""
    records = list(records)
    other = {r.cve_id for r in records} - {cve_id}
    if other:
        raise ValueError(f"registros de otra CVE en el registro de {cve_id}: {sorted(other)}")
    if any(r.observed_at is None for r in records):
        raise ValueError("registro sin 'observed_at': no ha pasado por el ejecutor")
    vulns = [r for r in records if r.entity is Entity.VULNERABILITY]
    vuln = max(vulns, key=lambda r: r.observed_at) if vulns else None
    signals = [r for r in records if r.entity is Entity.SIGNAL]

    affected: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    for rec in sorted(
        (r for r in records if r.entity is Entity.AFFECTED_PRODUCT),
        key=lambda r: (r.source, canonical_bytes(r.value)),
    ):
        item = _affected(rec)
        key = canonical_bytes(item)
        if key not in seen:
            seen.add(key)
            affected.append(item)

    fixed = _fixed_versions(affected)
    sig = _signals(signals, lists)
    sig["fix"] = {"available": bool(fixed), "versions": fixed}

    doc: dict[str, Any] = {
        "schema_version": OSV_SCHEMA_VERSION,
        "id": alert_id(cve_id),
        "aliases": _aliases(cve_id, records),
        "published": ts(published),
        "modified": ts(modified),
    }
    if vuln is not None and vuln.value.get("withdrawn_at"):
        doc["withdrawn"] = _ts_any(vuln.value["withdrawn_at"])
    severity = osv_severity(
        vuln.value.get("cvss_vector") if vuln else None,
        vuln.value.get("cvss_source") if vuln else None,
    )
    if severity:
        doc["severity"] = severity
    if affected:
        doc["affected"] = affected
    refs = _references(records)
    if refs:
        doc["references"] = refs
    doc["database_specific"] = {
        "vuln_sentinel": {
            "level": level.label,
            "impact_class": impact_class,
            "level_reason": list(level_reason),
            "level_history": level_history(history),
            "cwe": list(vuln.value.get("cwe") or []) if vuln else [],
            "signals": sig,
            "sources": _sources(records),
            "changes": [dict(c) for c in changes],
            "ai": {"used": False},
        }
    }
    return doc
