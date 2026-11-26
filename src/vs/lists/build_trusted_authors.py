"""Genera `config/trusted-exploit-authors.yaml` (PLAN.md §5.3, regla E4, F1a-0, R7).

Uso:
    uv run python -m vs.lists.build_trusted_authors --cutoff 2026-11-26 [--input metadata.json]

Sin `--input`, descarga `db/modules_metadata_base.json` de Metasploit Framework (BSD-3-Clause) a
`.cache/lists/`. La salida depende solo de los bytes de entrada y de la fecha de corte.

Implementa solo la parte (i) del criterio: autores de módulos `exploit/` con `disclosure_date` en
los últimos 24 meses. La parte (ii) (organizaciones acreditadas en `credits` que publican avisos
propios) queda fuera de la v1 por decisión de Juan (2026-11-26, revisión del PR #3).

Normalización de nombres (determinista, sin parecidos difusos):
- se quitan los bloques `<...>` que contienen un correo o una URL, las URL y los correos sueltos
  (regla 8: ningún correo en git); un `<...>` sin correo ni URL pasa a `(...)`;
- se colapsan los espacios y se quitan paréntesis o signos sueltos al final;
- la clave es el nombre en minúsculas (`casefold`); variantes distintas siguen siendo distintas.
Van a `needs_review` (nunca a `authors`): los nombres que parecen varias personas (coma, « and »,
«&») o genéricos, los autores que solo eran un correo y los módulos sin `disclosure_date`.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from vs.lists.common import ROOT, dump_yaml, fetch, months_before, parse_date, sha256_bytes

GENERATOR = "vs.lists.build_trusted_authors"
GENERATOR_VERSION = "1.1.0"
CRITERION_VERSION = 1
WINDOW_MONTHS = 24
MSF_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/"
    "db/modules_metadata_base.json"
)
OUTPUT = ROOT / "config" / "trusted-exploit-authors.yaml"

EMAIL_RE = re.compile(r"[\w.+-]+\s*(?:@|\[at\]|\(at\))\s*[\w-]+(?:\s*(?:\.|\[dot\])\s*[\w-]+)+")
URL_RE = re.compile(r"https?://\S+")
ANGLE_RE = re.compile(r"<([^<>]*)>")
MULTI_RE = re.compile(r",|&|\band\b", re.IGNORECASE)
GENERIC = frozenset({"unknown", "anonymous", "n/a", "none", "metasploit"})

HEADER = f"""\
Autores de exploits de confianza (regla E4, PLAN.md §5.3).

FICHERO GENERADO por {GENERATOR}
(src/vs/lists/build_trusted_authors.py). No se edita a mano: se cambia el criterio en el script,
se regenera y se revisa por PR (P-10).

CRITERIO (fijado el 2026-11-25, antes de mirar ningún caso; revisión R7):
La lista v1 es la unión de:
  (i)  autores (personas u organizaciones) de al menos un módulo de tipo `exploit/` de Metasploit
       Framework con `disclosure_date` en los últimos {WINDOW_MONTHS} meses hasta `cutoff_date`
       (campo `author` de db/modules_metadata_base.json);
  (ii) organizaciones acreditadas como descubridoras (`credits`) en registros CVE publicados en
       los últimos {WINDOW_MONTHS} meses que además publican avisos de vulnerabilidad propios.
       FUERA DE LA v1 (decisión de Juan, 2026-11-26): decidir si una organización «publica avisos
       propios» exige un juicio que el script no hace de forma determinista.

Notas de la v1:
  - E4 en v1 cuenta solo por enlace: el registro CVE o el aviso del fabricante enlazan el
    repositorio como exploit. Esta lista tiene nombres, no cuentas de GitHub; el mapeo
    autor → cuenta queda para la v2 (pregunta abierta).
  - La fecha es `disclosure_date` del módulo, no la fecha de aceptación en Metasploit (el metadata
    no la trae y `mod_time` cambia con ediciones masivas).
  - Los correos y URL de los autores se quitan (regla 8). Las variantes de un mismo autor que no
    coinciden en minúsculas quedan como entradas distintas: no hay parecidos difusos.
  - Los casos que la regla no resuelve van a `needs_review`, nunca a `authors`.

REGLAS DE MANTENIMIENTO:
  - Se commitea ANTES que cualquier fixture de prueba (p. ej. nginx2root).
  - Las altas y bajas manuales llevan motivo en el commit y en `manual_changes`.
"""


def normalize_author(raw: str) -> str:
    """Nombre sin correos ni URL, con espacios colapsados. Cadena vacía si no queda nada."""

    def _angle(m: re.Match) -> str:
        inner = m.group(1)
        if "@" in inner or "://" in inner or EMAIL_RE.search(inner):
            return ""
        return f"({inner.strip()})"

    text = ANGLE_RE.sub(_angle, raw)
    text = URL_RE.sub("", text)
    text = EMAIL_RE.sub("", text)
    text = re.sub(r"\(\s*\)", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"[\s(\-,;:]+$", "", text)
    return text.strip()


def review_reason(name: str) -> str | None:
    if name.casefold() in GENERIC:
        return "nombre genérico"
    if MULTI_RE.search(name):
        return "posible varias personas u organizaciones"
    return None


def _display(counter: Counter) -> str:
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def build(meta_bytes: bytes, cutoff: dt.date) -> dict:
    meta = json.loads(meta_bytes)
    start = months_before(cutoff, WINDOW_MONTHS)

    names: dict[str, Counter] = defaultdict(Counter)
    modules: dict[str, set[str]] = defaultdict(set)
    review: list[dict] = []
    exploit_total = in_window = 0
    for key in sorted(meta):
        mod = meta[key]
        if mod.get("type") != "exploit":
            continue
        exploit_total += 1
        fullname = mod.get("fullname") or key
        disclosed = parse_date(mod.get("disclosure_date"))
        if disclosed is None:
            review.append({"module": fullname, "reason": "módulo sin disclosure_date"})
            continue
        if not (start < disclosed <= cutoff):
            continue
        in_window += 1
        for raw in mod.get("author") or []:
            name = normalize_author(raw)
            if not name:
                review.append({"module": fullname, "reason": "autor identificado solo por correo"})
                continue
            k = name.casefold()
            names[k][name] += 1
            modules[k].add(fullname)

    authors = []
    for k in sorted(names):
        name = _display(names[k])
        mods = sorted(modules[k])
        reason = review_reason(name)
        if reason:
            review.append({"name": name, "reason": reason, "modules": mods})
            continue
        authors.append({"name": name, "source": "metasploit", "modules": mods})

    review.sort(key=lambda r: (r.get("name", "").casefold(), r.get("module", ""), r["reason"]))
    return {
        "criterion_version": CRITERION_VERSION,
        "generator": GENERATOR,
        "generator_version": GENERATOR_VERSION,
        "cutoff_date": cutoff.isoformat(),
        "window": {"months": WINDOW_MONTHS, "from_exclusive": start.isoformat()},
        "implemented_parts": ["i"],
        "inputs": [
            {
                "name": "metasploit-modules-metadata",
                "url": MSF_URL,
                "license": "BSD-3-Clause",
                "sha256": sha256_bytes(meta_bytes),
            }
        ],
        "stats": {
            "exploit_modules_total": exploit_total,
            "exploit_modules_in_window": in_window,
            "authors": len(authors),
            "needs_review": len(review),
        },
        "authors": authors,
        "needs_review": review,
        "manual_changes": [],
    }


def render(doc: dict) -> str:
    return dump_yaml(HEADER, doc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cutoff", required=True, type=dt.date.fromisoformat)
    ap.add_argument("--input", type=Path, help="metadata local (si no, se descarga)")
    ap.add_argument("--refresh", action="store_true", help="vuelve a descargar")
    ap.add_argument("--output", type=Path, default=OUTPUT)
    args = ap.parse_args(argv)
    data = (
        args.input.read_bytes()
        if args.input
        else fetch(MSF_URL, "modules_metadata_base.json", refresh=args.refresh)
    )
    doc = build(data, args.cutoff)
    args.output.write_text(render(doc), encoding="utf-8")
    print(f"{args.output}: {doc['stats']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
