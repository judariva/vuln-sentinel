"""Genera `config/exposed-products.yaml` a partir de CISA KEV (PLAN.md §5.2, F1a-0, R7).

Uso:
    uv run python -m vs.lists.build_exposed_products --cutoff 2026-11-26 [--input kev.json]

Sin `--input`, descarga el catálogo KEV a `.cache/lists/`. La salida depende solo de los bytes del
catálogo y de la fecha de corte.

Criterio (versión `CRITERION_VERSION`, reglas versión `RULES_VERSION`):
1. Se toman las entradas de KEV con `dateAdded` en la ventana (corte - 36 meses, corte].
2. Cada entrada recibe las categorías cuyas palabras clave (`CATEGORY_RULES`) aparecen en
   `vendorProject`, `product` o `vulnerabilityName`. Solo hay reglas: nada se añade a mano.
3. Un producto (vendor/product normalizados) tiene categoría si sus entradas categorizadas dan una
   sola y esa casa en al menos la mitad de sus entradas. Si dan varias, o casa en menos de la mitad,
   va a `needs_review`.
4. Entra en `products` si su fabricante suma al menos `THRESHOLD` entradas de esa categoría en la
   ventana. Si no, va a `below_threshold`.
5. Un producto sin categoría cuyo fabricante suma al menos `THRESHOLD` entradas en la ventana (de
   cualquier tipo) va a `needs_review`. El resto se ignora y solo se cuenta.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path

from vs.lists.common import ROOT, dump_yaml, fetch, months_before, parse_date, sha256_bytes, slug

GENERATOR = "vs.lists.build_exposed_products"
GENERATOR_VERSION = "1.0.0"
CRITERION_VERSION = 1
RULES_VERSION = 1
WINDOW_MONTHS = 36
THRESHOLD = 3
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT = ROOT / "config" / "exposed-products.yaml"

# Reglas v1: palabras clave de tipo de producto. Unas pocas son nombres de producto usados como
# tipo (esxi, vcenter, vsphere, hyper-v, connect secure, exchange server); se marcan para revisión
# en el PR. Se aplican sin distinguir mayúsculas, con límites de palabra. Cambiar una regla exige
# subir RULES_VERSION.
CATEGORY_RULES: dict[str, tuple[str, ...]] = {
    "vpn": (r"vpn", r"ssl[- ]?vpn", r"secure access", r"access gateway", r"connect secure"),
    "firewall": (r"firewall", r"waf", r"threat defense", r"security gateway", r"utm"),
    "load-balancer": (r"load[- ]balanc\w*", r"adc", r"application delivery", r"traffic manager"),
    "web-proxy": (r"proxy", r"reverse proxy", r"web server", r"http server", r"httpd"),
    "identity": (
        r"identity",
        r"sso",
        r"single sign[- ]on",
        r"access manager",
        r"active directory",
        r"federation",
        r"adfs",
    ),
    "hypervisor": (r"hypervisor", r"esxi", r"vcenter", r"vsphere", r"hyper-v", r"virtualization"),
    "cicd": (
        r"ci/cd",
        r"continuous integration",
        r"build server",
        r"devops",
        r"artifact repository",
        r"repository manager",
    ),
    "mail": (r"\w*mail\w*", r"exchange server"),
    "file-transfer": (r"file transfer", r"\w*ftp\w*", r"mft", r"file sharing"),
    "remote-access": (
        r"remote access",
        r"remote support",
        r"remote desktop",
        r"remote management",
        r"remote monitoring",
        r"rmm",
    ),
}

_COMPILED = {
    cat: [re.compile(rf"(?<![a-z0-9]){p}(?![a-z0-9])", re.IGNORECASE) for p in pats]
    for cat, pats in CATEGORY_RULES.items()
}

HEADER = f"""\
Productos expuestos a Internet de uso masivo (PLAN.md §5.2, `producto_expuesto`).

FICHERO GENERADO por {GENERATOR}
(src/vs/lists/build_exposed_products.py). No se edita a mano: se cambia el criterio o las reglas
en el script, se regenera y se revisa por PR (P-10).

CRITERIO v{CRITERION_VERSION} (fijado antes de mirar ningún caso; R7):
  1. Entradas de CISA KEV con `dateAdded` en los últimos {WINDOW_MONTHS} meses hasta `cutoff_date`.
  2. Cada entrada recibe las categorías cuyas palabras clave (`rules`, abajo) aparecen en
     vendorProject, product o vulnerabilityName. Son palabras de tipo de producto; algunas
     (esxi, vcenter, vsphere, hyper-v, connect secure, exchange server) son nombres de producto
     usados como tipo y Juan debe confirmarlas o quitarlas en la revisión.
  3. Un producto (vendor/product normalizados) tiene categoría si sus entradas dan una sola y esa
     casa en al menos la mitad de sus entradas. Entra en `products` si su fabricante suma al menos
     {THRESHOLD} entradas de esa categoría en la ventana; si no, va a `below_threshold`.
  4. Van a `needs_review` (NUNCA a `products`): los productos con varias categorías, aquellos cuya
     categoría casa en menos de la mitad de sus entradas y los productos sin categoría cuyo
     fabricante suma al menos {THRESHOLD} entradas en la ventana.
  5. Lo demás se ignora y solo se cuenta en `stats`.
  Pendiente (pregunta abierta del PR): «los servidores web/proxy y de identidad de mayor
  despliegue» del criterio anterior no tiene fuente determinista y no se aplica.

Formato de cada producto:
  - id: estable (fabricante--producto normalizados), nunca se reutiliza
    category: una de `categories`
    vendor / product: tal como aparecen en KEV (forma más frecuente)
    aliases: [{{vendor, product}} tal como aparecen en KEV]
    cpe: [prefijos cpe:2.3:<part>:<vendor>:<product>] (vacío en v1: KEV no trae CPE)
    purl: [purl sin versión] (vacío en v1)
    evidence: entradas de KEV que justifican el alta
"""


def classify(text: str) -> list[str]:
    """Categorías cuyas reglas casan con `text`, en el orden de CATEGORY_RULES."""
    return [cat for cat, pats in _COMPILED.items() if any(p.search(text) for p in pats)]


def _display(counter: Counter) -> str:
    """Forma más frecuente; a igualdad, la menor en orden alfabético."""
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def build(kev_bytes: bytes, cutoff: dt.date) -> dict:
    kev = json.loads(kev_bytes)
    start = months_before(cutoff, WINDOW_MONTHS)
    entries = kev["vulnerabilities"]

    products: dict[tuple[str, str], dict] = {}
    vendor_cat: Counter = Counter()
    vendor_total: Counter = Counter()
    in_window = 0
    for e in entries:
        added = parse_date(e.get("dateAdded"))
        if added is None or not (start < added <= cutoff):
            continue
        in_window += 1
        vendor, product = e["vendorProject"].strip(), e["product"].strip()
        vkey, pkey = slug(vendor), slug(product)
        cats = classify(f"{vendor} {product} {e.get('vulnerabilityName', '')}")
        p = products.setdefault(
            (vkey, pkey),
            {
                "vendor": Counter(),
                "product": Counter(),
                "pairs": set(),
                "cats": Counter(),
                "cves": set(),
            },
        )
        p["pairs"].add((vendor, product))
        p["vendor"][vendor] += 1
        p["product"][product] += 1
        p["cats"].update(cats)
        p["cves"].add(e["cveID"])
        vendor_total[vkey] += 1
        for c in cats:
            vendor_cat[(vkey, c)] += 1

    included, review, below = [], [], []
    ignored = 0
    for (vkey, pkey), p in sorted(products.items()):
        pid = f"{vkey}--{pkey}"
        aliases = _aliases(p)
        cats = sorted(p["cats"])
        cves = sorted(p["cves"])
        if len(cats) == 1 and p["cats"][cats[0]] * 2 < len(cves):
            reason = f"la categoría casa en {p['cats'][cats[0]]} de {len(cves)} entradas"
            review.append(_review(pid, p, cats, cves, reason))
        elif len(cats) == 1:
            cat = cats[0]
            n_cat = vendor_cat[(vkey, cat)]
            if n_cat >= THRESHOLD:
                included.append(
                    {
                        "id": pid,
                        "category": cat,
                        "vendor": _display(p["vendor"]),
                        "product": _display(p["product"]),
                        "aliases": aliases,
                        "cpe": [],
                        "purl": [],
                        "evidence": {
                            "kev_entries": len(cves),
                            "vendor_category_entries": n_cat,
                            "cves": cves,
                        },
                    }
                )
            else:
                below.append({"id": pid, "category": cat, "vendor_category_entries": n_cat})
        elif len(cats) > 1:
            review.append(_review(pid, p, cats, cves, "varias categorías"))
        elif vendor_total[vkey] >= THRESHOLD:
            reason = f"sin categoría; el fabricante suma {vendor_total[vkey]} entradas"
            review.append(_review(pid, p, cats, cves, reason))
        else:
            ignored += 1

    return {
        "criterion_version": CRITERION_VERSION,
        "generator": GENERATOR,
        "generator_version": GENERATOR_VERSION,
        "rules_version": RULES_VERSION,
        "cutoff_date": cutoff.isoformat(),
        "window": {"months": WINDOW_MONTHS, "from_exclusive": start.isoformat()},
        "threshold": THRESHOLD,
        "inputs": [
            {
                "name": "cisa-kev",
                "url": KEV_URL,
                "license": "CC0-1.0",
                "catalog_version": kev.get("catalogVersion"),
                "sha256": sha256_bytes(kev_bytes),
            }
        ],
        "categories": list(CATEGORY_RULES),
        "rules": {cat: list(pats) for cat, pats in CATEGORY_RULES.items()},
        "stats": {
            "kev_entries_total": len(entries),
            "kev_entries_in_window": in_window,
            "products_in_window": len(products),
            "products": len(included),
            "needs_review": len(review),
            "below_threshold": len(below),
            "ignored": ignored,
        },
        "products": included,
        "needs_review": review,
        "below_threshold": below,
    }


def _aliases(p: dict) -> list[dict]:
    return [{"vendor": v, "product": q} for v, q in sorted(p["pairs"])]


def _review(pid: str, p: dict, cats: list[str], cves: list[str], reason: str) -> dict:
    return {
        "id": pid,
        "vendor": _display(p["vendor"]),
        "product": _display(p["product"]),
        "categories_matched": {c: p["cats"][c] for c in cats},
        "reason": reason,
        "kev_entries": len(cves),
        "cves": cves,
    }


def render(doc: dict) -> str:
    return dump_yaml(HEADER, doc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cutoff", required=True, type=dt.date.fromisoformat)
    ap.add_argument("--input", type=Path, help="catálogo KEV local (si no, se descarga)")
    ap.add_argument("--refresh", action="store_true", help="vuelve a descargar")
    ap.add_argument("--output", type=Path, default=OUTPUT)
    args = ap.parse_args(argv)
    data = (
        args.input.read_bytes()
        if args.input
        else fetch(KEV_URL, "known_exploited_vulnerabilities.json", refresh=args.refresh)
    )
    doc = build(data, args.cutoff)
    args.output.write_text(render(doc), encoding="utf-8")
    print(f"{args.output}: {doc['stats']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
