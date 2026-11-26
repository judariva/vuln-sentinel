"""Pata de despliegue del criterio de `exposed-products` (criterio v2, punto 6).

Criterio original (F0, antes de mirar ningún caso): además de los productos de KEV, «los servidores
web/proxy y de identidad de mayor despliegue». En v2 se concreta así, FIJADO ANTES DE VER NINGÚN
RESULTADO de encuesta (2026-11-26):

  - Fuente: una encuesta pública, con fecha, de cuota de mercado o de despliegue en Internet, cuya
    licencia o términos permitan reutilizar la clasificación. Se registra su URL, su licencia y la
    fecha de la encuesta.
  - Se toman los `N` primeros nombres por cuota (`N = 5`), ordenados por cuota descendente y, a
    igualdad, por nombre.
  - Se guardan solo los nombres, el puesto, la fuente y la fecha (no las cifras de cuota).
  - Cada nombre entra con la categoría de la encuesta (`web-proxy` para servidores web y proxies
    inversos, `identity` para servidores de identidad o SSH).

Estado: NINGUNA FUENTE ACTIVA. Las encontradas no dan licencia de reutilización (ver `OPTIONS`),
así que no se inventa la lista: queda como pregunta abierta para Juan. El mecanismo es determinista
y se prueba con un fixture sintético.

Formato de una encuesta (JSON, normalizado a mano desde la fuente cuando se elija):
  {"source": str, "url": "https://...", "license": str, "survey_date": "YYYY-MM-DD",
   "category": "web-proxy" | "identity", "ranking": [{"name": str, "share": float}, ...]}
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
        "assessment": "sin licencia abierta; solo permite citar con referencia, fecha y enlace",
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
        "assessment": (
            "permite reproducir extractos con atribución; el acceso automático está restringido "
            "(robots.txt e identificación); no se localizó la última encuesta: SIN VERIFICAR"
        ),
    },
    {
        "name": "Shodan (facetas públicas)",
        "url": "https://www.shodan.io/terms",
        "terms_url": "https://www.shodan.io/terms",
        "checked": "2026-11-26",
        "quotes": [],
        "assessment": "la página de términos devolvió 404: SIN VERIFICAR",
    },
]


def _rank(survey: dict) -> list[dict]:
    ranking = sorted(survey["ranking"], key=lambda r: (-float(r["share"]), r["name"]))
    return [
        {"id": f"deployment--{slug(r['name'])}", "name": r["name"], "rank": i + 1}
        for i, r in enumerate(ranking[:N])
    ]


def build(survey_bytes: bytes | None) -> dict:
    """Sección `deployment_leg` del YAML."""
    base = {
        "criterion": (
            f"los {N} primeros nombres por cuota de una encuesta pública con fecha y licencia de "
            "reutilización (servidores web/proxy y de identidad o SSH)"
        ),
        "n": N,
    }
    if survey_bytes is None:
        return {
            **base,
            "status": "pending",
            "reason": (
                "ninguna fuente encontrada permite reutilizar la clasificación; decide Juan "
                "(pregunta abierta del PR)"
            ),
            "source": None,
            "options_found": OPTIONS,
            "products": [],
        }
    survey = json.loads(survey_bytes)
    category = survey["category"]
    if category not in SURVEY_CATEGORIES:
        raise ValueError(f"categoría de encuesta no admitida: {category}")
    if not str(survey["url"]).startswith("https://"):
        raise ValueError("la url de la encuesta debe ser https")
    return {
        **base,
        "status": "active",
        "source": {
            "name": survey["source"],
            "url": survey["url"],
            "license": survey["license"],
            "survey_date": dt.date.fromisoformat(survey["survey_date"]).isoformat(),
            "sha256": sha256_bytes(survey_bytes),
        },
        "products": [{**p, "category": category} for p in _rank(survey)],
    }
