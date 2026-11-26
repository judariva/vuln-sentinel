"""Conectores de fuentes (CMP-018, CMP-020, CMP-024).

Importar este paquete registra los conectores abiertos en `vs.sources.base.REGISTRY`. Cada
instancia activa los suyos en `config/instance.*.yaml` (ADR-0022).

La EUVD (SRC-014) no tiene conector: su licencia de reutilización sigue SIN VERIFICAR (T3).
"""

from vs.sources import (  # noqa: F401 - registran conectores
    cisa_kev,
    cvelistv5,
    epss,
    exploitdb,
    ghsa,
    github_search,
    metasploit,
    nomisec,
    osv,
)

# Conectores de datos abiertos de T3 y de exploits de T7.
BUILTIN = (
    "cisa_kev",
    "cvelistv5",
    "epss",
    "ghsa",
    "osv",
    "metasploit",
    "exploitdb",
    "nomisec",
    "github_search",
)
EXPLOIT_SOURCES = ("metasploit", "exploitdb", "nomisec", "github_search")
