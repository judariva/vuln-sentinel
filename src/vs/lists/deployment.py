"""Pata de despliegue del criterio de `exposed-products` (criterio v3, punto 7).

Criterio original (F0, antes de mirar ningún caso): además de los productos de KEV, «los servidores
web/proxy y de identidad de mayor despliegue». Se concreta así, FIJADO ANTES DE VER NINGÚN
RESULTADO (2026-11-26):

  - Fuente: un conjunto de datos o una encuesta pública, con fecha, que se pueda consultar sin
    credenciales de pago y cuyos términos permitan reutilizar la clasificación. Se registran su
    URL, sus términos y la fecha.
  - Se toman los `N` primeros nombres (`N = 5`) de productos que se instalan (se excluyen CDN y
    servicios), ordenados por cuota descendente y, a igualdad, por nombre.
  - Se guardan solo los nombres, el puesto, la fuente y la fecha (no las cifras de cuota).
  - Cada nombre entra con la categoría de la fuente (`web-proxy` para servidores web y proxies
    inversos, `identity` para servidores de identidad o SSH).

Estado v3: `web-proxy` desde Common Crawl (`vs.lists.deployment_cc`, decisión de Juan del
2026-11-26: fuente abierta primero). `identity`/SSH: sin fuente abierta, pendiente.

Formato de una encuesta (JSON):
  {"source": str, "url": "https://...", "license": str, "survey_date": "YYYY-MM-DD",
   "category": "web-proxy" | "identity", "ranking": [{"name": str, "share": float}, ...],
   opcionales: "terms_url", "method", "excluded", "needs_review" (mismo formato que ranking)}
"""

from __future__ import annotations

import datetime as dt
import json

from vs.lists.common import sha256_bytes, slug

N = 5
SURVEY_CATEGORIES = ("web-proxy", "identity")

# Fuentes consultadas el 2026-11-26 (citas literales leídas en la fuente).
OPTIONS: list[dict] = [
    {
        "name": "Common Crawl (ficheros WAT, cabecera Server)",
        "url": "https://data.commoncrawl.org/",
        "terms_url": "https://commoncrawl.org/terms-of-use",
        "checked": "2026-11-26",
        "quotes": [
            "CC grants you a limited, non-assignable, non-transferable, non-sublicensable, "
            "non-exclusive, limited license to access and use the Service subject to the terms "
            "and conditions of these ToU.",
            'the "Crawled Content") may be subject to separate terms of use or terms of service '
            "from the owners of such Crawled Content.",
            "CC strongly recommends that you obtain the advice of legal counsel before making any "
            "use, including commercial use, of the Service and/or the Crawled Content.",
        ],
        "credentials": "no: HTTPS anónimo en data.commoncrawl.org (comprobado con una petición "
        "por rango el 2026-11-26)",
        "assessment": (
            "se usa para web-proxy: acceso sin credenciales; los términos no prohíben el uso ni "
            "tratan los datos agregados; solo se publican nombres de producto, ningún contenido "
            "rastreado. Revisar en el PR"
        ),
    },
    {
        "name": "HTTP Archive (BigQuery)",
        "url": "https://httparchive.org/faq",
        "terms_url": None,
        "checked": "2026-11-26",
        "quotes": [
            "The HTTP Archive dataset is available publicly on BigQuery.",
            "In order to access the HTTP Archive via BigQuery, you'll need a Google account.",
            "BigQuery has a free tier that you can use to get started without enabling billing.",
        ],
        "credentials": "sí: cuenta de Google (sin facturación con la capa gratuita)",
        "assessment": (
            "no se usa: exige cuenta y no se encontró licencia de los datos (ni en el FAQ ni en "
            "la guía): SIN VERIFICAR"
        ),
    },
    {
        "name": "W3Techs, Usage statistics of web servers",
        "url": "https://w3techs.com/technologies/overview/web_server",
        "terms_url": "https://w3techs.com/terms_of_use",
        "checked": "2026-11-26",
        "quotes": [
            "All contents of this web site are Copyright © 2009-2026 Q-Success DI Gelbmann GmbH. "
            "All rights reserved.",
            "If you quote information from this web site, you must include a reference.",
            "If you publish the quote on the Internet, a link to the original page on this site "
            "must be provided.",
        ],
        "credentials": "no",
        "assessment": "alternativa para Juan, no se usa: sin licencia abierta",
    },
    {
        "name": "Netcraft Web Server Survey",
        "url": "https://www.netcraft.com/blog/",
        "terms_url": "https://www.netcraft.com/terms/",
        "checked": "2026-11-26",
        "quotes": [
            "All information and content on Netcraft's websites belongs to Netcraft, except as "
            "otherwise noted.",
            "Excerpts from Netcraft's public websites may be reproduced if Netcraft and the URL "
            "https://www.netcraft.com/ are attributed.",
        ],
        "credentials": "no",
        "assessment": "no se usa: acceso automático restringido; encuesta no localizada",
    },
]

IDENTITY_PENDING = {
    "category": "identity",
    "status": "pending",
    "reason": (
        "ninguna fuente abierta da el despliegue de servidores de identidad o SSH: Common Crawl "
        "solo ve HTTP; queda como pregunta abierta"
    ),
}


def _rank(survey: dict) -> list[dict]:
    ranking = sorted(survey["ranking"], key=lambda r: (-float(r["share"]), r["name"]))
    return [
        {"id": f"deployment--{slug(r['name'])}", "name": r["name"], "rank": i + 1}
        for i, r in enumerate(ranking[:N])
    ]


def _skipped(survey: dict, cut: float) -> list[dict]:
    """Nombres excluidos o sin clasificar con al menos la cuota del último que entra."""
    out = []
    for key, why in (("excluded", "servicio o CDN"), ("needs_review", "sin clasificar")):
        out += [
            {"name": r["name"], "reason": why}
            for r in survey.get(key) or []
            if float(r["share"]) >= cut
        ]
    return sorted(out, key=lambda r: r["name"])


def build(survey_bytes: bytes | None) -> dict:
    """Sección `deployment_leg` del YAML."""
    base = {
        "criterion": (
            f"los {N} primeros productos instalables por cuota de una fuente pública con fecha, "
            "consultable sin credenciales de pago y con términos que permitan reutilizar la "
            "clasificación (servidores web/proxy y de identidad o SSH)"
        ),
        "n": N,
    }
    if survey_bytes is None:
        return {
            **base,
            "status": "pending",
            "reason": "generado sin encuesta (`--survey`)",
            "source": None,
            "options_found": OPTIONS,
            "pending_parts": [IDENTITY_PENDING],
            "products": [],
            "skipped_above_cut": [],
        }
    survey = json.loads(survey_bytes)
    category = survey["category"]
    if category not in SURVEY_CATEGORIES:
        raise ValueError(f"categoría de encuesta no admitida: {category}")
    if not str(survey["url"]).startswith("https://"):
        raise ValueError("la url de la encuesta debe ser https")
    products = _rank(survey)
    shares = {r["name"]: float(r["share"]) for r in survey["ranking"]}
    cut = shares[products[-1]["name"]] if products else float("inf")
    source = {
        "name": survey["source"],
        "url": survey["url"],
        "license": survey["license"],
        "survey_date": dt.date.fromisoformat(survey["survey_date"]).isoformat(),
        "sha256": sha256_bytes(survey_bytes),
    }
    if survey.get("terms_url"):
        source["terms_url"] = survey["terms_url"]
    if survey.get("method"):
        m = survey["method"]
        source["method"] = {k: m[k] for k in sorted(m) if k != "files"}
    pending = [IDENTITY_PENDING] if category != "identity" else []
    return {
        **base,
        "status": "active",
        "source": source,
        "options_found": OPTIONS,
        "pending_parts": pending,
        "products": [{**p, "category": category} for p in products],
        "skipped_above_cut": _skipped(survey, cut),
    }
