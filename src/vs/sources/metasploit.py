"""Metasploit (SRC-008): módulos que referencian una CVE. E1 si el módulo es `exploit/`.

Licencia: el fichero `LICENSE` del repositorio (https://github.com/rapid7/metasploit-framework,
leído el 2026-11-26) dice «Files: * / Copyright: 2006-2026, Rapid7, Inc. / License: BSD-3-clause»
y «The Metasploit Framework is provided under the 3-clause BSD license provided at the end of this
file.» Clase `open`; el aviso de Rapid7 va en `NOTICE`.

Lectura: `db/modules_metadata_base.json` (un objeto por módulo). **Solo metadatos**: nunca se
descarga ni se lee el código del módulo. Se guarda el nombre completo (`fullname`, p. ej.
`exploit/linux/http/x` o `auxiliary/dos/http/x`), el tipo, el rango y la fecha de divulgación. No
se guardan los autores (traen correos) ni la descripción.

El tipo decide la regla (`vs.rules.exploit`): `exploit/` es E1; `auxiliary/dos/*` nunca cuenta
(ADR-0013). La fecha del dato es el `mod_time` más reciente del fichero.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

from vs.sources.base import Connector, LicenseClass, Record, is_cve_id, register
from vs.sources.http import SourceError, get_json

DEFAULT_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/"
    "modules_metadata_base.json"
)
DEFAULT_BLOB_URL = "https://github.com/rapid7/metasploit-framework/blob/master"
MIN_MODULES = 1


def parse_mod_time(value: Any, what: str) -> datetime:
    """`mod_time` viene como «2025-05-21 08:32:40 +0000»."""
    if not isinstance(value, str) or not value:
        raise SourceError(f"{what}: mod_time ausente")
    for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value.strip(), fmt).astimezone(UTC)
        except ValueError:
            continue
    raise SourceError(f"{what}: mod_time no válido: {value!r}")


@register
class MetasploitConnector(Connector):
    name = "metasploit"
    license_class = LicenseClass.OPEN
    # Rapid7 fusiona módulos casi a diario; una semana sin cambios se trata como avería.
    freshness_threshold = timedelta(days=7)

    def fetch(self) -> Iterator[dict[str, Any]]:
        url = self.config.get("url", DEFAULT_URL)
        data = get_json(self.transport, url)
        if not isinstance(data, dict) or len(data) < MIN_MODULES:
            raise SourceError("Metasploit: el metadata no es un objeto de módulos")
        for key, mod in data.items():
            if not isinstance(mod, dict) or not isinstance(mod.get("fullname"), str):
                raise SourceError(f"Metasploit: módulo sin 'fullname': {key!r}")
            mod_time = parse_mod_time(mod.get("mod_time"), f"Metasploit {mod['fullname']}")
            if self.data_as_of is None or mod_time > self.data_as_of:
                self.data_as_of = mod_time
            yield mod

    def normalize(self, raw: dict[str, Any]) -> Iterable[Record]:
        refs = raw.get("references") or []
        if not isinstance(refs, list):
            raise SourceError(f"Metasploit: 'references' no es una lista en {raw['fullname']}")
        cves = sorted({r for r in refs if is_cve_id(r)})
        if not cves:
            self.count("sin_cve")
            return
        fullname = raw["fullname"].strip("/")
        mod_type = str(raw.get("type") or fullname.split("/", 1)[0])
        path = raw.get("path")
        url = None
        if isinstance(path, str) and path.startswith("/modules/") and ".." not in path:
            url = self.config.get("blob_url", DEFAULT_BLOB_URL) + path
        if fullname.startswith("auxiliary/dos/"):
            self.count("dos")
        notes = raw.get("notes") if isinstance(raw.get("notes"), dict) else {}
        value = {
            "origin": "metasploit",
            "path": fullname,
            "type": mod_type,
            "rank": raw.get("rank"),
            "disclosure_date": raw.get("disclosure_date"),
            "check": bool(raw.get("check")),
            "post_auth": bool(raw.get("post_auth")),
            "reliability": list(notes.get("Reliability") or []),
        }
        for cve in cves:
            yield Record(
                source=self.name,
                cve_id=cve,
                kind="exploit",
                license_class=self.license_class,
                value=value,
                source_published_at=None,  # el metadata no da la fecha de alta del módulo
                url=url,
            )
