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
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from vs.agent.tools import Document, Fetcher

DEFAULT_MIN_QUOTE_CHARS = 20

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
    reason: str  # ok | domain | unavailable | too_short | not_found | lines


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


class CitationVerifier:
    def __init__(self, fetcher: Fetcher, min_quote_chars: int = DEFAULT_MIN_QUOTE_CHARS) -> None:
        self.fetcher = fetcher
        self.min_quote_chars = min_quote_chars

    def check(self, citation: Mapping[str, Any]) -> CitationCheck:
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
        return CitationCheck(url, True, "ok")

    def check_claims(self, claims: list[Mapping[str, Any]]) -> list[ClaimCheck]:
        return [ClaimCheck(c, [self.check(cit) for cit in c.get("citations", [])]) for c in claims]
