"""Validación del esquema de las listas generadas. Devuelve la lista de errores (vacía = válido)."""

from __future__ import annotations

import datetime as dt
import re

SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*--[a-z0-9]+(?:-[a-z0-9]+)*$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
CPE_RE = re.compile(r"^cpe:2\.3:[aoh]:[^:*]+:[^:*]+$")


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
    for cat, r in rules.items():
        if not isinstance(r, dict) or not isinstance(r.get("type"), list):
            errors.append(f"rules.{cat}: sin lista `type`")
        elif not isinstance(r.get("brand"), list):
            errors.append(f"rules.{cat}: sin lista `brand`")
        elif not isinstance(r.get("name", []), list):
            errors.append(f"rules.{cat}: `name` no es una lista")
    if set(doc.get("precedence") or []) != set(categories):
        errors.append("`precedence` no cubre exactamente `categories`")
    if not (doc.get("canonicalization") or {}).get("rules"):
        errors.append("`canonicalization.rules` vacío")
    if not isinstance(doc.get("manual_changes"), list):
        errors.append("`manual_changes` no es una lista")
    threshold = doc.get("threshold")
    if isinstance(threshold, int):  # criterio v1/v2: umbral único
        threshold = dict.fromkeys(categories, threshold)
    if (
        not isinstance(threshold, dict)
        or set(threshold) != set(categories)
        or not all(isinstance(n, int) and n >= 1 for n in threshold.values())
    ):
        errors.append("`threshold` no válido: un entero ≥ 1 por categoría")
        threshold = {}
    seen: set[str] = set()
    sections = ("products", "needs_review", "below_threshold")
    for section in sections:
        if not isinstance(doc.get(section), list):
            errors.append(f"`{section}` no es una lista")
            continue
        for item in doc[section]:
            _check_id(item.get("id", ""), section, seen, errors)
    out = doc.get("out_of_scope")
    if not isinstance(out, list):
        errors.append("`out_of_scope` no es una lista")
    else:
        for pid in out:
            _check_id(pid, "out_of_scope", seen, errors)
    for p in doc.get("products") or []:
        _check_product(p, categories, threshold, errors)
    for r in doc.get("needs_review") or []:
        if not r.get("reason"):
            errors.append(f"{r.get('id')}: needs_review sin motivo")
    _check_deployment(doc.get("deployment_leg"), categories, errors)
    stats = doc.get("stats") or {}
    for section in (*sections, "out_of_scope"):
        if stats.get(section) != len(doc.get(section) or []):
            errors.append(f"stats.{section} no coincide con la lista")
    return errors


def _check_id(pid: str, section: str, seen: set[str], errors: list[str]) -> None:
    if not ID_RE.match(str(pid)):
        errors.append(f"{section}: id no válido {pid!r}")
    if pid in seen:
        errors.append(f"id repetido {pid!r}")
    seen.add(pid)


def _check_product(p: dict, categories: list, threshold: dict, errors: list[str]) -> None:
    pid = p.get("id")
    if p.get("category") not in categories:
        errors.append(f"{pid}: categoría desconocida")
    if p.get("category_source") not in ("name", "descriptions"):
        errors.append(f"{pid}: `category_source` no válido")
    if not p.get("matched"):
        errors.append(f"{pid}: sin reglas que lo justifiquen")
    for key in ("vendor", "product"):
        if not p.get(key):
            errors.append(f"{pid}: falta `{key}`")
    if not p.get("aliases"):
        errors.append(f"{pid}: sin alias")
    for key in ("cpe", "purl", "cna", "names", "abbreviations"):
        if not isinstance(p.get(key), list):
            errors.append(f"{pid}: `{key}` no es una lista")
    cpes = p.get("cpe") or []
    if not all(CPE_RE.match(str(c)) for c in cpes):
        errors.append(f"{pid}: CPE mal formado")
    if not cpes and not p.get("cpe_missing_reason"):
        errors.append(f"{pid}: sin CPE y sin motivo")
    if "cna_missing_reason" in p and (p.get("cna") or not p["cna_missing_reason"]):
        errors.append(f"{pid}: `cna_missing_reason` vacío o con pares del CNA")
    for c in p.get("cna") or []:
        if not (isinstance(c, dict) and c.get("vendor") and c.get("product")):
            errors.append(f"{pid}: par del CNA incompleto")
    ev = p.get("evidence") or {}
    cves = ev.get("cves") or []
    if not cves or not all(CVE_RE.match(c) for c in cves):
        errors.append(f"{pid}: evidencia sin CVE válidos")
    limit = threshold.get(p.get("category"))
    if isinstance(limit, int) and ev.get("vendor_category_entries", 0) < limit:
        errors.append(f"{pid}: por debajo del umbral")


def _check_deployment(leg: object, categories: list, errors: list[str]) -> None:
    if not isinstance(leg, dict):
        errors.append("falta `deployment_leg`")
        return
    n = leg.get("n")
    if not isinstance(n, int) or n < 1:
        errors.append("deployment_leg: `n` no válido")
    products = leg.get("products")
    if not isinstance(products, list):
        errors.append("deployment_leg: `products` no es una lista")
        return
    if leg.get("status") == "pending":
        if products or not leg.get("reason"):
            errors.append("deployment_leg pendiente: sin motivo o con productos")
    elif leg.get("status") == "active":
        src = leg.get("source") or {}
        if not str(src.get("url", "")).startswith("https://") or not src.get("license"):
            errors.append("deployment_leg: fuente sin url https o sin licencia")
        if not SHA_RE.match(str(src.get("sha256", ""))) or not src.get("survey_date"):
            errors.append("deployment_leg: fuente sin hash o sin fecha")
        if isinstance(n, int) and len(products) > n:
            errors.append("deployment_leg: más productos que `n`")
        for i, p in enumerate(products):
            if p.get("rank") != i + 1 or p.get("category") not in categories:
                errors.append(f"deployment_leg: producto {i} mal formado")
    else:
        errors.append("deployment_leg: `status` no válido")


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
