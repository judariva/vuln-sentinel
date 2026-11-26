"""Pares del CNA y prefijos CPE de la pata de despliegue (criterio v4, decisión de Juan, T14).

Cada entrada de `deployment_leg` (un nombre como «nginx», sacado de la cabecera `Server`) recibe
sus pares vendor/product del CNA y sus prefijos CPE, como en el criterio v2, de los registros
cvelistV5. Método, fijado antes de mirar el resultado y escrito en el YAML (`PAIRS_METHOD`):

1. Registros: los de cvelistV5 con `state = PUBLISHED` y `datePublished` en los últimos
   `WINDOW_MONTHS` meses hasta la fecha de corte (`(corte - 36 meses, corte]`).
2. «Contiene el nombre»: los términos del nombre (`slug`, separados por guiones) aparecen seguidos
   y completos entre los términos de:
   - el `product` de un par de `containers.cna.affected` (el `vendor` no cuenta: en «Apache HTTP
     Server» el nombre está en el producto; un fabricante no es un producto);
   - el componente `product` de un prefijo `cpe:2.3:<part>:<vendor>:<product>` de los `cpes` del
     CNA o de los ADP (por la misma razón, el `vendor` del CPE no cuenta).
3. Una entrada recibe los pares y prefijos que contienen su nombre, con el número de registros de
   la ventana en que aparece cada par. Sin ninguno, lleva `cna_missing_reason` y no casa nada.

Entrada: el volcado diario de cvelistV5 (release `…_all_CVEs_at_midnight.zip.zip`). El recorrido
deja en caché solo los registros que casan (`.cache/lists/cvelistV5-deployment/`) y el YAML lleva
el hash de esos registros y el del volcado. La salida depende solo de esos bytes y del corte.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import re
import zipfile
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import BinaryIO

from vs.lists import cvelist
from vs.lists.common import CACHE_DIR, months_before, parse_date, slug

WINDOW_MONTHS = 36
CACHE = CACHE_DIR / "cvelistV5-deployment"
SOURCE_FILE = "_source.json"
RELEASES_URL = "https://github.com/CVEProject/cvelistV5/releases"

PAIRS_METHOD = {
    "version": 1,
    "source": "cvelistV5, volcado diario completo (release `…_all_CVEs_at_midnight.zip.zip`)",
    "records": (
        f"state PUBLISHED y datePublished en (cutoff_date - {WINDOW_MONTHS} meses, cutoff_date]"
    ),
    "match": (
        "los términos del nombre (slug) aparecen seguidos y completos en el `product` de un par "
        "de containers.cna.affected, o en el componente product de un prefijo CPE 2.3 del CNA o "
        "de los ADP; el vendor no cuenta"
    ),
    "output": (
        "pares vendor/product del CNA y prefijos cpe:2.3:<part>:<vendor>:<product> que contienen "
        "el nombre, con el número de registros de la ventana de cada par"
    ),
}


def tokens(text: str) -> list[str]:
    s = slug(text)
    return s.split("-") if s else []


def contains(hay: list[str], needle: list[str]) -> bool:
    """¿`needle` aparece seguido y completo dentro de `hay`?"""
    n = len(needle)
    return n > 0 and any(hay[i : i + n] == needle for i in range(len(hay) - n + 1))


def cpe_product_tokens(prefix: str) -> list[str]:
    product = prefix.split(":")[4]
    return tokens(re.sub(r"[_\\]+", " ", product))


def in_window(data: dict, cutoff: dt.date) -> bool:
    meta = data.get("cveMetadata") or {}
    if meta.get("state") != "PUBLISHED":
        return False
    published = parse_date(meta.get("datePublished"))
    start = months_before(cutoff, WINDOW_MONTHS)
    return published is not None and start < published <= cutoff


def _record_hits(record: bytes, names: dict[str, list[str]]) -> dict[str, dict]:
    """Por nombre: pares del CNA y prefijos CPE del registro que lo contienen."""
    parsed = cvelist.parse(record)
    out: dict[str, dict] = {}
    for name, needle in names.items():
        cna = [tuple(p) for p in parsed["cna"] if contains(tokens(p[1]), needle)]
        cpe = [c for c in parsed["cpe"] if contains(cpe_product_tokens(c), needle)]
        if cna or cpe:
            out[name] = {"cna": cna, "cpe": cpe}
    return out


def _quick(raw: bytes, needles: Iterable[list[str]]) -> bool:
    """Filtro previo barato: algún nombre tiene todos sus términos en el texto del registro."""
    low = raw.lower()
    return any(all(t.encode() in low for t in needle) for needle in needles)


def _members(path: Path | BinaryIO) -> Iterator[tuple[str, bytes]]:
    """(nombre, bytes) de cada `CVE-*.json` del volcado, entrando en el zip interior si lo hay."""
    with zipfile.ZipFile(path) as outer:
        for info in outer.infolist():
            if info.filename.endswith(".zip"):
                with outer.open(info) as fh:
                    inner_bytes = fh.read()
                with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner:
                    for i in inner.infolist():
                        if re.search(r"CVE-\d{4}-\d{4,}\.json$", i.filename):
                            yield i.filename, inner.read(i)
            elif re.search(r"CVE-\d{4}-\d{4,}\.json$", info.filename):
                yield info.filename, outer.read(info)


def scan_bulk(path: Path | BinaryIO, names: Iterable[str], cutoff: dt.date) -> dict[str, bytes]:
    """Registros del volcado (en la ventana) que contienen alguno de los nombres."""
    needles = {n: tokens(n) for n in names}
    out: dict[str, bytes] = {}
    for filename, raw in _members(path):
        if not _quick(raw, needles.values()):
            continue
        data = json.loads(raw)
        if not in_window(data, cutoff):
            continue
        if _record_hits(raw, needles):
            cve = Path(filename).stem
            out[cve] = raw
    return out


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def save_cache(records: dict[str, bytes], source: dict, cache_dir: Path = CACHE) -> None:
    """Sustituye la caché por estos registros y su procedencia."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    for old in cache_dir.glob("*.json"):
        old.unlink()
    for cve, raw in records.items():
        (cache_dir / f"{cve}.json").write_bytes(raw)
    (cache_dir / SOURCE_FILE).write_text(json.dumps(source, sort_keys=True), encoding="utf-8")


def load_cache(cache_dir: Path = CACHE) -> tuple[dict[str, bytes], dict] | None:
    src = cache_dir / SOURCE_FILE
    if not src.exists():
        return None
    records = {p.stem: p.read_bytes() for p in sorted(cache_dir.glob("CVE-*.json")) if p.is_file()}
    return records, json.loads(src.read_text(encoding="utf-8"))


def pairs_for(names: Iterable[str], records: dict[str, bytes], cutoff: dt.date) -> dict[str, dict]:
    """Por nombre: `cna` (con registros por par), `cpe` y `records`, o el motivo si no hay."""
    needles = {n: tokens(n) for n in names}
    cna: dict[str, Counter] = {n: Counter() for n in needles}
    cpe: dict[str, set[str]] = {n: set() for n in needles}
    seen: dict[str, set[str]] = {n: set() for n in needles}
    for cve in sorted(records):
        raw = records[cve]
        if not in_window(json.loads(raw), cutoff):
            continue
        for name, hit in _record_hits(raw, needles).items():
            seen[name].add(cve)
            cna[name].update(set(hit["cna"]))
            cpe[name].update(hit["cpe"])
    out: dict[str, dict] = {}
    for name in needles:
        item: dict = {
            "cna": [
                {"vendor": v, "product": p, "records": n}
                for (v, p), n in sorted(cna[name].items(), key=lambda kv: kv[0])
            ],
            "cpe": sorted(cpe[name]),
            "records": len(seen[name]),
        }
        if not item["cna"]:
            item["cna_missing_reason"] = (
                "ningún registro de la ventana tiene un par del CNA cuyo producto contenga "
                "el nombre"
            )
        if not item["cpe"]:
            item["cpe_missing_reason"] = (
                "ningún registro de la ventana tiene un CPE cuyo producto contenga el nombre"
            )
        out[name] = item
    return out
