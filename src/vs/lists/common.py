"""Utilidades comunes de los generadores de listas.

Reglas de reproducibilidad:
- la salida depende solo de los bytes de entrada y de la fecha de corte, que se pasa explícita;
- no se escribe la hora de ejecución: dos ejecuciones con las mismas entradas dan el mismo fichero;
- el hash SHA-256 de cada entrada va en el YAML, junto con la versión del generador.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import unicodedata
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
CACHE_DIR = ROOT / ".cache" / "lists"


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def fetch(url: str, name: str, cache_dir: Path = CACHE_DIR, refresh: bool = False) -> bytes:
    """Descarga `url` a `cache_dir/name` (si no está ya) y devuelve sus bytes."""
    if not url.startswith("https://"):
        raise ValueError(f"solo https: {url}")
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / name
    if refresh or not target.exists():
        # S310: el esquema se comprueba arriba (solo https).
        req = urllib.request.Request(url, headers={"User-Agent": "vuln-sentinel-lists"})  # noqa: S310
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
            target.write_bytes(resp.read())
    return target.read_bytes()


def parse_date(value: str | None) -> dt.date | None:
    """Fecha ISO (YYYY-MM-DD al principio de la cadena) o None si no hay o no es válida."""
    if not value:
        return None
    try:
        return dt.date.fromisoformat(value[:10])
    except ValueError:
        return None


def months_before(day: dt.date, months: int) -> dt.date:
    """Mismo día del mes `months` meses antes (ajustado al último día si no existe)."""
    year, month = divmod(day.year * 12 + (day.month - 1) - months, 12)
    month += 1
    for d in (day.day, 30, 29, 28):
        try:
            return dt.date(year, month, d)
        except ValueError:
            continue
    raise ValueError(day)


def slug(text: str) -> str:
    """Nombre normalizado: ASCII, minúsculas, guiones."""
    norm = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", norm.lower()).strip("-")


def dump_yaml(header: str, doc: dict) -> str:
    body = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100)
    lines = [f"# {line}".rstrip() for line in header.strip("\n").splitlines()]
    return "\n".join(lines) + "\n" + body
