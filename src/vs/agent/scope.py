"""Alcance de una investigación: qué hosts puede pedir el agente y cuáles son aviso oficial.

Regla determinista (T10b), sin ningún dominio de fabricante escrito a mano:

- **Lista permitida** = la fija (`config/allowed-domains.yaml`) más los hosts de las referencias
  del registro cvelistV5 de **esa** CVE que el CNA etiqueta `vendor-advisory`.
- **Avisos oficiales** = los fijos de autoridad (`official_advisory_domains`, p. ej.
  `www.cisa.gov`) más esos mismos hosts del CNA, salvo los de alojamiento de código
  (`code_hosting_domains`): un repositorio nunca es un aviso oficial, aunque el CNA lo etiquete.

Solo cuenta el contenedor `cna`: los `adp` no los escribe quien asigna la CVE. Una referencia que
no cumple la forma de `https_host` (http, IP, puerto, credenciales) no abre nada y se registra.

El alcance se calcula **antes** de llamar al modelo, vale solo para esa investigación y se guarda
en la traza y en el expediente. Un host abierto para una CVE no vale para otra.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from vs.agent.tools import DomainPolicy, https_host

VENDOR_ADVISORY_TAG = "vendor-advisory"


def vendor_advisory_urls(record: Mapping[str, Any] | None) -> tuple[str, ...]:
    """URL de las referencias del CNA con la etiqueta `vendor-advisory`, sin repetir y en orden."""
    if not isinstance(record, Mapping):
        return ()
    containers = record.get("containers")
    cna = containers.get("cna") if isinstance(containers, Mapping) else None
    refs = cna.get("references") if isinstance(cna, Mapping) else None
    out: list[str] = []
    for ref in refs if isinstance(refs, list) else []:
        if not isinstance(ref, Mapping):
            continue
        tags = ref.get("tags")
        url = ref.get("url")
        tagged = isinstance(tags, list) and VENDOR_ADVISORY_TAG in tags
        if tagged and isinstance(url, str) and url not in out:
            out.append(url)
    return tuple(out)


@dataclass(frozen=True)
class CveScope:
    cve_id: str
    policy: DomainPolicy  # lista permitida de esta investigación
    official: frozenset[str]  # hosts que cuentan como aviso oficial en esta investigación
    cve_hosts: frozenset[str]  # hosts abiertos por los avisos del CNA de esta CVE
    rejected_urls: tuple[str, ...]  # referencias `vendor-advisory` que no abren nada

    def trace(self) -> dict[str, Any]:
        """Lo que se registra en la traza y en el expediente (solo hosts, nunca contenido)."""
        return {
            "cve_hosts": sorted(self.cve_hosts),
            "official_domains": sorted(self.official),
            "rejected_vendor_urls": list(self.rejected_urls),
        }


def build_scope(
    cve_id: str,
    vendor_urls: Sequence[str],
    base: DomainPolicy,
    fixed_official: Iterable[str],
    code_hosting: Iterable[str],
) -> CveScope:
    hosts: set[str] = set()
    rejected: list[str] = []
    for url in vendor_urls:
        host = https_host(url)
        if host is None:
            rejected.append(str(url)[:300])
        else:
            hosts.add(host)
    code = frozenset(d.lower() for d in code_hosting)
    official = frozenset(d.lower() for d in fixed_official) | (frozenset(hosts) - code)
    return CveScope(
        cve_id=cve_id,
        policy=base.extended(hosts) if hosts else base,
        official=official,
        cve_hosts=frozenset(hosts),
        rejected_urls=tuple(rejected),
    )
