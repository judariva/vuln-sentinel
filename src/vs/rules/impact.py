"""`impact_class` determinista a partir de CWE, CVSS y SSVC (PLAN.md §5.2, R3, ADR-0013).

| Clase          | Criterio (cualquiera)                                                         |
|----------------|-------------------------------------------------------------------------------|
| `rce`          | CWE ∈ RCE_CWES con CVSS C:H e I:H, o SSVC `technical_impact = total`          |
| `auth_bypass`  | CWE ∈ AUTH_BYPASS_CWES con PR:N                                               |
| `arbitrary_rw` | CWE ∈ ARBITRARY_RW_CWES con C:H o I:H                                         |
| `other`        | El resto, incluidos los solo DoS (C:N/I:N o CWE de DoS) y fugas de bajo impacto |

Las clases se comprueban en ese orden y gana la primera. El CVSS se lee en v4.0 (VC/VI), v3.x
(C/I) y v2 (C/I con C=Complete como H; Au:N como PR:N; sin UI).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

RCE_CWES = frozenset({77, 78, 94, 95, 502, 787, 416, 190, 191, 122, 120, 917, 1336})
AUTH_BYPASS_CWES = frozenset({287, 288, 290, 294, 306, 862, 863, 639, 1390})
ARBITRARY_RW_CWES = frozenset({22, 23, 36, 73, 434, 611, 918})
# Solo documentan qué cae en `other`; no hace falta comprobarlos: lo que no es de las otras tres
# clases ya es `other`.
DOS_CWES = frozenset({400, 770, 835, 674, 1333})


class ImpactClass(StrEnum):
    """Valores del ENUM `impact_class` del modelo."""

    RCE = "rce"
    AUTH_BYPASS = "auth_bypass"
    ARBITRARY_RW = "arbitrary_rw"
    OTHER = "other"


@dataclass(frozen=True)
class Cvss:
    """Las métricas que usan las reglas, normalizadas a la notación de CVSS 3.x."""

    av: str | None = None
    pr: str | None = None
    ui: str | None = None
    c: str | None = None
    i: str | None = None

    @property
    def network_unauth_no_ui(self) -> bool:
        """`AV:N/PR:N/UI:N`. Con un dato ausente es False: no se presume lo peor ni lo mejor."""
        return self.av == "N" and self.pr == "N" and self.ui == "N"


_V2_CIA = {"C": "H", "P": "L", "N": "N"}
_V2_AU = {"N": "N", "S": "L", "M": "H"}


def parse_cvss(vector: str | None) -> Cvss:
    """Lee un vector CVSS v2, v3.x o v4.0. Un vector vacío o ilegible da `Cvss()` (todo None)."""
    if not vector:
        return Cvss()
    parts: dict[str, str] = {}
    for item in vector.strip().split("/"):
        key, sep, val = item.partition(":")
        if sep:
            parts[key.strip().upper()] = val.strip().upper()
    version = parts.pop("CVSS", None)
    if version is not None and version.startswith("4"):  # UI en v4: N, P o A
        return Cvss(
            av=parts.get("AV"),
            pr=parts.get("PR"),
            ui=parts.get("UI"),
            c=parts.get("VC"),
            i=parts.get("VI"),
        )
    if version is not None:  # 3.0 / 3.1
        return Cvss(
            av=parts.get("AV"),
            pr=parts.get("PR"),
            ui=parts.get("UI"),
            c=parts.get("C"),
            i=parts.get("I"),
        )
    if "AU" in parts:  # v2: sin prefijo y con Au
        return Cvss(
            av=parts.get("AV"),
            pr=_V2_AU.get(parts.get("AU", "")),
            ui=None,
            c=_V2_CIA.get(parts.get("C", "")),
            i=_V2_CIA.get(parts.get("I", "")),
        )
    return Cvss()


_CWE_RE = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)


def cwe_numbers(cwes: Iterable[str | int] | None) -> frozenset[int]:
    """`["CWE-787", "NVD-CWE-Other", 416]` → `{787, 416}`. Ignora lo que no es un CWE numérico."""
    out: set[int] = set()
    for c in cwes or ():
        if isinstance(c, int):
            out.add(c)
            continue
        m = _CWE_RE.match(str(c).strip())
        if m:
            out.add(int(m.group(1)))
    return frozenset(out)


def impact_class(
    cwes: Iterable[str | int] | None,
    cvss_vector: str | None,
    technical_impact: str | None = None,
) -> ImpactClass:
    """Clase de impacto de una CVE (tabla del §5.2). Determinista: mismas entradas, misma clase."""
    nums = cwe_numbers(cwes)
    cvss = parse_cvss(cvss_vector)
    if (nums & RCE_CWES and cvss.c == "H" and cvss.i == "H") or technical_impact == "total":
        return ImpactClass.RCE
    if nums & AUTH_BYPASS_CWES and cvss.pr == "N":
        return ImpactClass.AUTH_BYPASS
    if nums & ARBITRARY_RW_CWES and (cvss.c == "H" or cvss.i == "H"):
        return ImpactClass.ARBITRARY_RW
    return ImpactClass.OTHER


def rce_sin_auth(impact: ImpactClass, cvss_vector: str | None) -> bool:
    """`impact_class = rce` ∧ CVSS `AV:N/PR:N/UI:N` (§5.2)."""
    return impact is ImpactClass.RCE and parse_cvss(cvss_vector).network_unauth_no_ui
