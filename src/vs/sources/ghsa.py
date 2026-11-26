"""GitHub Advisory Database (SRC-005): rangos de ecosistemas.

Licencia: «The GitHub Advisory Database is licensed under the Creative Commons Attribution 4.0
license. The attribution term may be fulfilled by linking to the GitHub Advisory Database at
https://github.com/advisories or to individual GitHub Advisory Database records used, prefixed by
https://github.com/advisories.» (https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features,
leído el 2026-11-26). Clase `open`; cada registro lleva su `html_url` para la atribución.

Lectura: `GET /advisories?type=reviewed&sort=updated&direction=desc`, página a página (cabecera
`Link`), hasta llegar a un aviso no posterior al cursor. Si se acaban las páginas permitidas antes
de llegar al cursor, la ejecución es UNKNOWN (fail-closed), no una lectura parcial.

Token opcional: la configuración nombra la variable de entorno (`token_env`), nunca el valor.
Sin CVE no hay fila en el modelo (la clave es `cve_id`): esos avisos se cuentan y se saltan.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

from vs.sources.base import Connector, Entity, LicenseClass, Record, is_cve_id, register
from vs.sources.http import SourceError, SourceIncomplete, get_ok, parse_json, parse_ts

DEFAULT_API_URL = "https://api.github.com/advisories"
DEFAULT_MAX_PAGES = 20
PER_PAGE = 100
_NEXT_RE = re.compile(r'<([^>]+)>\s*;\s*rel="next"')


def _next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    m = _NEXT_RE.search(link_header)
    return m.group(1) if m else None


@register
class GhsaConnector(Connector):
    name = "ghsa"
    license_class = LicenseClass.OPEN
    # Se revisan avisos a diario; un día entero sin cambios es raro y se trata como avería.
    freshness_threshold = timedelta(hours=24)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        env = self.config.get("token_env")
        token = os.environ.get(env) if env else None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def fetch(self) -> Iterator[dict[str, Any]]:
        api = self.config.get("api_url", DEFAULT_API_URL)
        max_pages = int(self.config.get("max_pages", DEFAULT_MAX_PAGES))
        query = {"type": "reviewed", "sort": "updated", "direction": "desc", "per_page": PER_PAGE}
        url: str | None = f"{api}?{urlencode(query)}"
        headers = self._headers()
        pages = 0
        while url is not None:
            if not url.startswith(api):
                raise SourceError(f"GHSA: enlace de paginación fuera de {api}: {url}")
            if pages >= max_pages:
                if self.since is not None:
                    raise SourceIncomplete(
                        f"GHSA: {max_pages} páginas sin llegar al cursor {self.since.isoformat()}"
                    )
                return  # carga inicial: se lee hasta el tope (ver informe de T3)
            resp = get_ok(self.transport, url, headers=headers)
            page = parse_json(resp.body, url)
            if not isinstance(page, list):
                raise SourceError("GHSA: la respuesta no es una lista")
            pages += 1
            for adv in page:
                if not isinstance(adv, dict):
                    raise SourceError("GHSA: aviso que no es un objeto")
                updated = parse_ts(adv.get("updated_at"), f"GHSA {adv.get('ghsa_id')} updated_at")
                if self.data_as_of is None or updated > self.data_as_of:
                    self.data_as_of = updated
                if self.since is not None and updated <= self.since:
                    return
                yield adv
            url = _next_link(resp.header("Link"))

    def normalize(self, raw: dict[str, Any]) -> Iterable[Record]:
        ghsa_id = raw.get("ghsa_id")
        cve = raw.get("cve_id")
        if not cve:
            self.count("sin_cve")
            return
        if not is_cve_id(cve):
            raise SourceError(f"GHSA: cve_id no válido en {ghsa_id}: {cve!r}")
        published = parse_ts(raw.get("published_at"), f"GHSA {ghsa_id} published_at")
        if raw.get("withdrawn_at"):
            self.count("retirados")
            return
        for v in raw.get("vulnerabilities") or []:
            pkg = (v or {}).get("package") or {}
            yield Record(
                source=self.name,
                cve_id=cve,
                kind="affected_product",
                license_class=self.license_class,
                entity=Entity.AFFECTED_PRODUCT,
                value={
                    "vendor": None,
                    "product": pkg.get("name"),
                    "cpe": None,
                    "purl": None,
                    "ecosystem": pkg.get("ecosystem"),
                    "ranges": [
                        {
                            "type": "ghsa",
                            "vulnerable_version_range": v.get("vulnerable_version_range"),
                            "first_patched_version": v.get("first_patched_version"),
                        }
                    ],
                    "range_source": f"ghsa:{ghsa_id}",
                },
                source_published_at=published,
                url=raw.get("html_url"),
            )
