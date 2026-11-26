"""CISA KEV (SRC-002): explotación activa confirmada, señal de nivel A.

Licencia: CC0 1.0 («The KEV database is distributed under the Creative Commons 0 1.0 License»,
https://github.com/cisagov/kev-data/blob/main/LICENSE, leído el 2026-11-26). Sin logos de CISA ni
del DHS. Clase `open`.

`dateAdded` es una fecha sin hora (R4): `source_published_at` queda NULL y la fecha va en `value`.
La fecha del dato es `dateReleased` del catálogo.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import timedelta
from typing import Any
from urllib.parse import quote

from vs.sources.base import Connector, Entity, LicenseClass, Record, is_cve_id, register
from vs.sources.http import SourceError, get_json, parse_ts

DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve="


@register
class CisaKevConnector(Connector):
    name = "cisa_kev"
    license_class = LicenseClass.OPEN
    # CISA puede pasar varios días sin publicar una versión nueva del catálogo.
    freshness_threshold = timedelta(days=7)

    def fetch(self) -> Iterator[dict[str, Any]]:
        url = self.config.get("url", DEFAULT_URL)
        data = get_json(self.transport, url)
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise SourceError("KEV: falta la lista 'vulnerabilities'")
        vulns = data["vulnerabilities"]
        count = data.get("count")
        if count is not None and count != len(vulns):
            raise SourceError(f"KEV: 'count' = {count} pero hay {len(vulns)} entradas")
        self.data_as_of = parse_ts(data.get("dateReleased"), "KEV dateReleased")
        version = data.get("catalogVersion")
        for item in vulns:
            if not isinstance(item, dict):
                raise SourceError("KEV: entrada que no es un objeto")
            yield {**item, "_catalog_version": version}

    def normalize(self, raw: dict[str, Any]) -> Iterable[Record]:
        cve = raw.get("cveID")
        if not is_cve_id(cve):
            raise SourceError(f"KEV: cveID no válido: {cve!r}")
        date_added = raw.get("dateAdded")
        # Valida la fecha aunque se guarde como texto.
        parse_ts(date_added, f"KEV dateAdded de {cve}")
        value = {
            "date_added": date_added,
            "due_date": raw.get("dueDate"),
            "known_ransomware_campaign_use": raw.get("knownRansomwareCampaignUse"),
            "vendor_project": raw.get("vendorProject"),
            "product": raw.get("product"),
            "cwes": list(raw.get("cwes") or []),
            "catalog_version": raw.get("_catalog_version"),
        }
        yield Record(
            source=self.name,
            cve_id=cve,
            kind="kev_cisa",
            license_class=self.license_class,
            value=value,
            entity=Entity.SIGNAL,
            source_published_at=None,
            url=CATALOG_URL + quote(cve),
        )
