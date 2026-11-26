"""Registros de cvelistV5 para rellenar `cpe` y los pares vendor/product del CNA (criterio v2).

Fuente: https://github.com/CVEProject/cvelistV5 (registros CVE JSON 5). El README dice: «You may
search, download, and use the content hosted in this repository, per the CVE Program Terms of
Use». Los términos (https://www.cve.org/Legal/TermsOfUse; texto leído el 2026-11-26 en el código
fuente público de cve.org, CVEProject/cve-website, src/views/Legal/TermsOfUse.vue) dicen: «MITRE
hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
copyright license to reproduce, prepare derivative works of, publicly display, publicly perform,
sublicense, and distribute Common Vulnerabilities and Exposures (CVE). Any copy you make for such
purposes is authorized provided that you reproduce MITRE's copyright designation and this license
in any such copy.»

De cada registro se toman solo:
- los pares vendor/product de `containers.cna.affected` (sin «n/a»);
- los prefijos `cpe:2.3:<part>:<vendor>:<product>` de `affected[].cpes` del CNA y de los ADP.

Las descargas van a `.cache/lists/cvelistV5/`. La salida depende solo de los bytes de los registros.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
from pathlib import Path

from vs.lists.common import CACHE_DIR, fetch

REPO_URL = "https://github.com/CVEProject/cvelistV5"
RAW_URL = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{cve}.json"
)
TERMS_URL = "https://www.cve.org/Legal/TermsOfUse"
LICENSE = "CVE Program Terms of Use (MITRE)"
NOTICE = (
    "Contiene datos de registros CVE. CVE® es una marca de The MITRE Corporation. Usados según "
    "los CVE Program Terms of Use (https://www.cve.org/Legal/TermsOfUse): «MITRE hereby grants "
    "you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright "
    "license to reproduce, prepare derivative works of, publicly display, publicly perform, "
    "sublicense, and distribute Common Vulnerabilities and Exposures (CVE). Any copy you make for "
    "such purposes is authorized provided that you reproduce MITRE's copyright designation and "
    "this license in any such copy.»"
)
CACHE = CACHE_DIR / "cvelistV5"
CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")


def record_url(cve: str) -> str:
    m = CVE_RE.match(cve)
    if not m:
        raise ValueError(cve)
    year, num = m.groups()
    return RAW_URL.format(year=year, bucket=int(num) // 1000, cve=cve)


def fetch_records(
    cves: list[str], cache_dir: Path = CACHE, refresh: bool = False
) -> tuple[dict[str, bytes], list[str]]:
    """Descarga (o lee de caché) los registros. Devuelve (registros, CVE sin registro)."""
    records: dict[str, bytes] = {}
    missing: list[str] = []
    for cve in sorted(set(cves)):
        try:
            records[cve] = fetch(
                record_url(cve), f"{cve}.json", cache_dir=cache_dir, refresh=refresh
            )
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
            missing.append(cve)
    return records, missing


def load_cached(cves: list[str], cache_dir: Path = CACHE) -> dict[str, bytes]:
    """Registros ya descargados (sin red)."""
    out = {}
    for cve in sorted(set(cves)):
        path = cache_dir / f"{cve}.json"
        if path.exists():
            out[cve] = path.read_bytes()
    return out


def records_hash(records: dict[str, bytes]) -> str:
    """SHA-256 de las líneas «CVE<TAB>sha256(registro)», ordenadas por CVE."""
    lines = "".join(
        f"{cve}\t{hashlib.sha256(records[cve]).hexdigest()}\n" for cve in sorted(records)
    )
    return "sha256:" + hashlib.sha256(lines.encode()).hexdigest()


def cpe_prefix(cpe: str) -> str | None:
    """`cpe:2.3:<part>:<vendor>:<product>` o None si no es un CPE 2.3 con vendor y product."""
    parts = cpe.split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    part, vendor, product = parts[2], parts[3], parts[4]
    if part not in ("a", "o", "h") or vendor in ("", "*", "-") or product in ("", "*", "-"):
        return None
    return ":".join(["cpe", "2.3", part, vendor, product])


def parse(record: bytes) -> dict:
    """Pares vendor/product del CNA y prefijos CPE (CNA y ADP) de un registro."""
    data = json.loads(record)
    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}
    pairs: set[tuple[str, str]] = set()
    cpes: set[str] = set()
    for a in cna.get("affected") or []:
        vendor, product = str(a.get("vendor") or "").strip(), str(a.get("product") or "").strip()
        if vendor and product and "n/a" not in (vendor.lower(), product.lower()):
            pairs.add((vendor, product))
    for container in [cna, *(containers.get("adp") or [])]:
        for a in container.get("affected") or []:
            for c in a.get("cpes") or []:
                prefix = cpe_prefix(str(c))
                if prefix:
                    cpes.add(prefix)
    return {"cna": sorted(pairs), "cpe": sorted(cpes)}
