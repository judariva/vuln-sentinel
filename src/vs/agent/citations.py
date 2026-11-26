"""Verificador determinista de citas (CTL-002, THR-003).

Cada afirmación del expediente lleva citas `{url, quote}`. Una cita es válida solo si:
- la URL está en la lista de dominios permitidos;
- el contenido de esa URL se ha descargado (si el agente no la leyó, el verificador la descarga
  con las mismas reglas que la herramienta);
- la cita, **normalizada**, aparece literal en el contenido normalizado; y tiene un mínimo de
  caracteres (una cita de dos palabras no prueba nada);
- si trae `line_start`/`line_end`, aparece dentro de esas líneas del documento.

Normalizar es: NFKC, minúsculas (casefold), comillas y guiones tipográficos a ASCII y espacios
colapsados. No es una búsqueda difusa: o está, o no está.

Una afirmación con **alguna** cita no válida se rechaza entera.

Una afirmación `exploited` tiene que ser **sobre esta CVE** (T10b): el identificador exacto de la
CVE tiene que aparecer en la cita o a ±N líneas de ella en el documento (`cve_window_lines` de
`config/agent.yaml`). Si no, la cita se rechaza con `other_cve`: una frase literal del catálogo KEV
entero o de un aviso de otra CVE no prueba que esta se explote.
"""

from __future__ import annotations

import bisect
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from vs.agent.tools import Document, Fetcher

DEFAULT_MIN_QUOTE_CHARS = 20
DEFAULT_CVE_WINDOW_LINES = 3

_TRANSLATE = str.maketrans(
    {
        "‘": "'",
        "’": "'",
        "‚": "'",
        "‛": "'",
        "“": '"',
        "”": '"',
        "„": '"',
        "«": '"',
        "»": '"',
        "‐": "-",
        "‑": "-",
        "‒": "-",
        "–": "-",
        "—": "-",
        "−": "-",
        " ": " ",
    }
)


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_TRANSLATE).casefold()
    return " ".join(text.split())


@dataclass(frozen=True)
class CitationCheck:
    url: str
    ok: bool
    reason: str  # ok | domain | unavailable | too_short | not_found | lines | other_cve


@dataclass
class ClaimCheck:
    claim: Mapping[str, Any]
    citations: list[CitationCheck] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.citations) and all(c.ok for c in self.citations)

    @property
    def kind(self) -> str:
        return str(self.claim.get("kind"))


def _in_lines(doc: Document, quote: str, start: int, end: int) -> bool:
    lines = doc.text.splitlines()
    if start < 1 or end < start or start > len(lines):
        return False
    window = "\n".join(lines[start - 1 : end])
    return quote in normalize(window)


def locate(
    lines: list[str], quote: str, lo: int = 1, hi: int | None = None
) -> list[tuple[int, int]]:
    """Tramos `(inicio, fin)` (1-based) de `lines[lo..hi]` donde aparece la cita normalizada.

    `quote` ya viene normalizada. Una cita puede ocupar varias líneas: se normaliza cada línea, se
    unen con un espacio (lo mismo que hace `normalize` con los saltos de línea) y cada aparición
    se traduce a la primera y la última línea que toca.
    """
    hi = len(lines) if hi is None else min(hi, len(lines))
    starts: list[int] = []  # desplazamiento de cada línea no vacía en `joined`
    numbers: list[int] = []  # su número de línea
    parts: list[str] = []
    pos = 0
    for n in range(max(lo, 1), hi + 1):
        norm = normalize(lines[n - 1])
        if not norm:
            continue
        if parts:
            pos += 1  # el espacio que las une
        starts.append(pos)
        numbers.append(n)
        parts.append(norm)
        pos += len(norm)
    joined = " ".join(parts)
    out: list[tuple[int, int]] = []
    if not quote:
        return out
    i = joined.find(quote)
    while i != -1:
        first = bisect.bisect_right(starts, i) - 1
        last = bisect.bisect_right(starts, i + len(quote) - 1) - 1
        out.append((numbers[first], numbers[last]))
        i = joined.find(quote, i + 1)
    return sorted(set(out))


def cve_pattern(cve_id: str) -> re.Pattern[str]:
    """El identificador exacto, normalizado: `CVE-2099-0012` no casa con `CVE-2099-00123`."""
    return re.compile(r"(?<![0-9a-z])" + re.escape(normalize(cve_id)) + r"(?![0-9])")


def mentions_cve(doc: Document, quote: str, cve_id: str, window: int) -> bool:
    """La CVE aparece en la cita o a ±`window` líneas de alguna aparición de la cita."""
    pat = cve_pattern(cve_id)
    if pat.search(quote):
        return True
    lines = doc.text.splitlines()
    for start, end in locate(lines, quote):
        lo, hi = max(start - window, 1), min(end + window, len(lines))
        if pat.search(normalize("\n".join(lines[lo - 1 : hi]))):
            return True
    return False


class CitationVerifier:
    def __init__(
        self,
        fetcher: Fetcher,
        min_quote_chars: int = DEFAULT_MIN_QUOTE_CHARS,
        *,
        cve_id: str | None = None,
        cve_window_lines: int = DEFAULT_CVE_WINDOW_LINES,
    ) -> None:
        self.fetcher = fetcher
        self.min_quote_chars = min_quote_chars
        self.cve_id = cve_id
        self.cve_window_lines = cve_window_lines

    def document(self, url: str) -> Document | None:
        """El documento ya descargado de una cita (para comprobaciones posteriores)."""
        return self.fetcher.corpus.get(url)

    def check(self, citation: Mapping[str, Any], *, about_cve: bool = False) -> CitationCheck:
        url = str(citation.get("url", ""))
        quote = normalize(str(citation.get("quote", "")))
        if not self.fetcher.policy.allows(url):
            return CitationCheck(url, False, "domain")
        if len(quote) < self.min_quote_chars:
            return CitationCheck(url, False, "too_short")
        doc = self.fetcher.fetch(url)
        if not isinstance(doc, Document):
            return CitationCheck(url, False, "unavailable")
        if quote not in normalize(doc.text):
            return CitationCheck(url, False, "not_found")
        start, end = citation.get("line_start"), citation.get("line_end")
        if start is not None or end is not None:
            start = int(start if start is not None else end)
            end = int(end if end is not None else start)
            if not _in_lines(doc, quote, start, end):
                return CitationCheck(url, False, "lines")
        if about_cve:
            if self.cve_id is None:
                raise ValueError("comprobar que una cita es sobre la CVE exige cve_id")
            if not mentions_cve(doc, quote, self.cve_id, self.cve_window_lines):
                return CitationCheck(url, False, "other_cve")
        return CitationCheck(url, True, "ok")

    def check_claims(self, claims: list[Mapping[str, Any]]) -> list[ClaimCheck]:
        out = []
        for c in claims:
            # Solo `exploited` exige que la cita sea sobre esta CVE (sube a A).
            about = self.cve_id is not None and str(c.get("kind")) == "exploited"
            out.append(
                ClaimCheck(c, [self.check(x, about_cve=about) for x in c.get("citations", [])])
            )
        return out
