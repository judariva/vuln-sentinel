"""Conectores de fuentes (CMP-018, CMP-020).

Importar este paquete registra los conectores abiertos en `vs.sources.base.REGISTRY`. Cada
instancia activa los suyos en `config/instance.*.yaml` (ADR-0022).

La EUVD (SRC-014) no tiene conector: su licencia de reutilización sigue SIN VERIFICAR (T3).
"""

from vs.sources import cisa_kev, cvelistv5, epss, ghsa, osv  # noqa: F401 - registran conectores

BUILTIN = ("cisa_kev", "cvelistv5", "epss", "ghsa", "osv")
