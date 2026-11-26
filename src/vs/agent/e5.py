"""E5 en código: cuándo unas líneas citadas de un PoC pueden llevar una CVE de C a B (T10b).

Un repositorio nuevo puede publicar código falso con líneas «convincentes». Por eso, además de que
la cita sea literal y con líneas (`citations.py`), una afirmación `exploit_impact` solo vale para
E5 si se cumplen las dos condiciones siguientes, comprobadas sin el modelo:

1. **Repositorio no sospechoso.** La URL citada se traduce a `dueño/repo` de GitHub y ese
   repositorio tiene veredicto de las heurísticas `poc_suspicious` de T7 (`vs.sources.poc`) con
   `suspicious: false`. Si es `true` → no sube. Si no hay veredicto (no inspeccionado, `null`) o la
   URL no se puede traducir a un repositorio → no se puede decidir.
2. **La cita es código que hace algo.** De las líneas que cubre la cita se toman los nombres de
   código (fuera de comentarios y cadenas) que **también están en la cita**, y entre ellos tiene que
   haber una llamada de red o el payload. Si la cita no incluye ningún nombre de código (solo
   comentarios, docstrings o cadenas) → no sube. Si incluye código pero sin ninguna de esas marcas
   → no se puede decidir.

«No se puede decidir» deja el expediente en `needs_human` y no sube nada.

Para Python se usa `tokenize` (comentarios, cadenas y nombres exactos). Para el resto de
lenguajes, una aproximación conservadora: se quitan comentarios de línea y de bloque y los
literales de cadena, y se buscan las marcas en lo que queda.
"""

from __future__ import annotations

import io
import re
import tokenize
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import unquote, urlsplit

from vs.agent.citations import locate, normalize
from vs.agent.tools import Document

# Llamadas de red (nombres exactos, en minúsculas) y nombres que contienen el payload.
NETWORK_NAMES = frozenset(
    {
        "socket",
        "create_connection",
        "connect",
        "send",
        "sendall",
        "sendto",
        "recv",
        "urlopen",
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
        "httpconnection",
        "httpsconnection",
        "http_request",
        "curl",
        "wget",
        "fetch",
        "dial",
        "netcat",
        "ncat",
    }
)
PAYLOAD_NAMES = ("payload", "shellcode")

_WORD = re.compile(r"[a-z_][a-z0-9_]*")
_STRINGS = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`')
_LINE_COMMENT = re.compile(r"^\s*(#|//|--|;|rem\s|<!--)", re.IGNORECASE)
_HOSTS_REPO = {
    "raw.githubusercontent.com": 0,  # /dueño/repo/rama/ruta
    "github.com": 0,  # /dueño/repo/...
    "api.github.com": 1,  # /repos/dueño/repo/...
}
_REPO_PART = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


class Verdict(StrEnum):
    CONFIRMED = "confirmed"  # puede subir de C a B
    NO = "no"  # decidido: no sube
    UNDECIDED = "undecided"  # no se puede decidir: needs_human, no sube


@dataclass(frozen=True)
class E5Check:
    verdict: Verdict
    reason: str
    repo: str | None = None


def repo_of(url: str) -> str | None:
    """`dueño/repo` en minúsculas de una URL de GitHub; None si no es una."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host not in _HOSTS_REPO:
        return None
    segs = [unquote(s) for s in parts.path.split("/") if s]
    skip = _HOSTS_REPO[host]
    if skip and (len(segs) < 1 or segs[0] != "repos"):
        return None
    segs = segs[skip:]
    if len(segs) < 2 or not all(_REPO_PART.match(s) for s in segs[:2]):
        return None
    if segs[0] in (".", "..") or segs[1] in (".", ".."):
        return None
    return f"{segs[0]}/{segs[1]}".lower()


def poc_repos_from_signals(values: list[Mapping[str, Any]]) -> dict[str, bool | None]:
    """`{dueño/repo: suspicious}` desde las señales `exploit` de GitHub (T7).

    Si un repositorio aparece varias veces, gana lo más desfavorable: `true` sobre `null` sobre
    `false`. Así una señal sin inspeccionar nunca «limpia» otra sospechosa.
    """
    rank = {True: 2, None: 1, False: 0}
    out: dict[str, bool | None] = {}
    for v in values:
        if str(v.get("origin", "")).lower() != "github" or not isinstance(v.get("repo"), str):
            continue
        s = v.get("suspicious")
        s = s if isinstance(s, bool) else None
        key = v["repo"].lower()
        if key not in out or rank[s] > rank[out[key]]:
            out[key] = s
    return out


# -- qué es código en las líneas citadas -------------------------------------------------------


def _python_code_words(text: str) -> dict[int, set[str]] | None:
    """Por línea, los nombres de código (sin comentarios ni cadenas). None si no se tokeniza."""
    words: dict[int, set[str]] = {}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.NAME:
                words.setdefault(tok.start[0], set()).add(tok.string.lower())
            elif tok.type == tokenize.OP:
                words.setdefault(tok.start[0], set())
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None
    return words


def _generic_code_words(text: str) -> dict[int, set[str]]:
    words: dict[int, set[str]] = {}
    in_block = False
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw
        if in_block:
            end = line.find("*/")
            if end == -1:
                continue
            line, in_block = line[end + 2 :], False
        while "/*" in line:
            a = line.find("/*")
            b = line.find("*/", a + 2)
            if b == -1:
                line, in_block = line[:a], True
                break
            line = line[:a] + " " + line[b + 2 :]
        if _LINE_COMMENT.match(line):
            continue
        line = _STRINGS.sub(" ", line)
        line = re.split(r"\s#|//", line, maxsplit=1)[0]
        if line.strip():
            words[n] = set(_WORD.findall(line.lower()))
    return words


def _is_python(url: str) -> bool:
    return urlsplit(url).path.lower().endswith((".py", ".pyw"))


def _marks(words: set[str]) -> bool:
    return bool(words & NETWORK_NAMES) or any(p in w for w in words for p in PAYLOAD_NAMES)


def check_lines(doc: Document, citation: Mapping[str, Any]) -> E5Check:
    """¿Las líneas que cubre la cita son código con red o payload?"""
    start = citation.get("line_start")
    end = citation.get("line_end", start)
    if start is None:
        return E5Check(Verdict.NO, "no_lines")
    end = start if end is None else end
    lines = doc.text.splitlines()
    spans = locate(lines, normalize(str(citation.get("quote", ""))), int(start), int(end))
    if not spans:
        return E5Check(Verdict.NO, "quote_not_in_lines")
    if _is_python(doc.url):
        words = _python_code_words(doc.text)
        if words is None:
            return E5Check(Verdict.UNDECIDED, "python_not_tokenizable")
    else:
        words = _generic_code_words(doc.text)
    cited = {n for a, b in spans for n in range(a, b + 1)}
    code = set().union(*(words[n] for n in cited if n in words))
    # Solo cuenta el código que está DENTRO de la cita: un comentario al final de una línea de
    # código no convierte la cita en código.
    quoted = code & set(_WORD.findall(normalize(str(citation.get("quote", "")))))
    if not quoted:
        return E5Check(Verdict.NO, "only_comments")
    if _marks(quoted):
        return E5Check(Verdict.CONFIRMED, "code_with_network_or_payload")
    return E5Check(Verdict.UNDECIDED, "code_without_network_or_payload")


def check_citation(
    doc: Document, citation: Mapping[str, Any], poc_repos: Mapping[str, bool | None]
) -> E5Check:
    """Las dos condiciones de E5 para una cita ya verificada como literal."""
    repo = repo_of(doc.url)
    if repo is None:
        return E5Check(Verdict.UNDECIDED, "not_a_known_repo_url")
    if repo not in poc_repos or poc_repos[repo] is None:
        return E5Check(Verdict.UNDECIDED, "repo_not_inspected", repo)
    if poc_repos[repo] is True:
        return E5Check(Verdict.NO, "poc_suspicious", repo)
    lines = check_lines(doc, citation)
    return E5Check(lines.verdict, lines.reason, repo)


def combine(checks: list[E5Check]) -> E5Check:
    """Una afirmación con varias citas: basta un NO para que no suba; si no, un UNDECIDED decide."""
    if not checks:
        return E5Check(Verdict.NO, "no_citations")
    for v in (Verdict.NO, Verdict.UNDECIDED):
        for c in checks:
            if c.verdict is v:
                return c
    return checks[0]
