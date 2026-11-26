"""Validación del esquema de las listas generadas. Devuelve la lista de errores (vacía = válido)."""

from __future__ import annotations

import datetime as dt
import re

SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*--[a-z0-9]+(?:-[a-z0-9]+)*$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def _common(doc: dict, errors: list[str]) -> None:
    for key in ("criterion_version", "generator", "generator_version", "cutoff_date", "inputs"):
        if key not in doc:
            errors.append(f"falta `{key}`")
    try:
        dt.date.fromisoformat(str(doc.get("cutoff_date")))
    except ValueError:
        errors.append("`cutoff_date` no es una fecha ISO")
    inputs = doc.get("inputs") or []
    if not inputs:
        errors.append("`inputs` vacío")
    for i, inp in enumerate(inputs):
        if not SHA_RE.match(str(inp.get("sha256", ""))):
            errors.append(f"inputs[{i}]: hash ausente o mal formado")
        if not str(inp.get("url", "")).startswith("https://"):
            errors.append(f"inputs[{i}]: url no https")
        if not inp.get("license"):
            errors.append(f"inputs[{i}]: falta la licencia")


def validate_exposed(doc: dict) -> list[str]:
    errors: list[str] = []
    _common(doc, errors)
    categories = doc.get("categories") or []
    rules = doc.get("rules") or {}
    if set(categories) != set(rules):
        errors.append("`categories` y `rules` no coinciden")
    threshold = doc.get("threshold")
    if not isinstance(threshold, int) or threshold < 1:
        errors.append("`threshold` no válido")
    seen: set[str] = set()
    for section in ("products", "needs_review", "below_threshold"):
        if not isinstance(doc.get(section), list):
            errors.append(f"`{section}` no es una lista")
            continue
        for item in doc[section]:
            pid = item.get("id", "")
            if not ID_RE.match(pid):
                errors.append(f"{section}: id no válido {pid!r}")
            if pid in seen:
                errors.append(f"id repetido {pid!r}")
            seen.add(pid)
    for p in doc.get("products") or []:
        pid = p.get("id")
        if p.get("category") not in categories:
            errors.append(f"{pid}: categoría desconocida")
        for key in ("vendor", "product"):
            if not p.get(key):
                errors.append(f"{pid}: falta `{key}`")
        if not p.get("aliases"):
            errors.append(f"{pid}: sin alias")
        for key in ("cpe", "purl"):
            if not isinstance(p.get(key), list):
                errors.append(f"{pid}: `{key}` no es una lista")
        ev = p.get("evidence") or {}
        cves = ev.get("cves") or []
        if not cves or not all(CVE_RE.match(c) for c in cves):
            errors.append(f"{pid}: evidencia sin CVE válidos")
        if isinstance(threshold, int) and ev.get("vendor_category_entries", 0) < threshold:
            errors.append(f"{pid}: por debajo del umbral")
    stats = doc.get("stats") or {}
    for section in ("products", "needs_review", "below_threshold"):
        if stats.get(section) != len(doc.get(section) or []):
            errors.append(f"stats.{section} no coincide con la lista")
    return errors


def validate_authors(doc: dict) -> list[str]:
    errors: list[str] = []
    _common(doc, errors)
    if not isinstance(doc.get("manual_changes"), list):
        errors.append("`manual_changes` no es una lista")
    authors = doc.get("authors")
    if not isinstance(authors, list):
        return [*errors, "`authors` no es una lista"]
    keys: set[str] = set()
    for a in authors:
        name = a.get("name", "")
        if not name:
            errors.append("autor sin nombre")
        if EMAIL_RE.search(name) or "://" in name:
            errors.append(f"autor con correo o URL: {name!r}")
        if name.casefold() in keys:
            errors.append(f"autor repetido: {name!r}")
        keys.add(name.casefold())
        if not a.get("modules"):
            errors.append(f"{name!r}: sin módulos que lo justifiquen")
    for r in doc.get("needs_review") or []:
        if EMAIL_RE.search(str(r)):
            errors.append("needs_review contiene un correo")
    stats = doc.get("stats") or {}
    if stats.get("authors") != len(authors):
        errors.append("stats.authors no coincide")
    return errors
