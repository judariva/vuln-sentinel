"""Heurísticas `poc_suspicious` de un repositorio de PoC (PLAN.md §5.3) y su lector de metadatos.

**El código nunca se clona ni se ejecuta** (CTL-005, THR-005). Todo sale de la API de GitHub: el
repositorio y su dueño (metadatos), el árbol de ficheros (rutas y tamaños), las releases (nombres de
los ficheros adjuntos) y, para unos pocos ficheros de texto pequeños, la API de contenidos, que
devuelve el fichero en base64. Ese contenido se decodifica a texto y solo se le pasan expresiones
regulares: no se interpreta, no se compila, no se escribe en disco.

Señales (cualquiera marca el repositorio como sospechoso):

| Razón | Qué mira |
|---|---|
| `binary` | ficheros o releases con extensión de binario, ejecutable o comprimido; texto con NUL |
| `blob` | base64, `\\xNN` o `0xNN,` seguidos de al menos `blob_kb` KB; descodificar y ejecutar |
| `curl_sh` | `curl … \\| sh` y equivalentes; descargas de dominios fuera de la lista permitida |
| `new_account` | la cuenta tenía menos de 30 días cuando creó el repositorio |
| `readme_only` | ningún fichero de código: solo README, licencia, imágenes o texto |
| `fork` | el repositorio es un fork (de otro PoC) |

Veredicto: `suspicious = True` si hay alguna razón; `False` solo si la inspección fue completa y
limpia; `None` si no se pudo inspeccionar del todo (sin presupuesto, error de la API, árbol
truncado o ficheros sin leer). `None` nunca se presenta como «limpio».
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote, urlsplit

from vs.sources.http import SourceError, Transport, get_ok, parse_json, parse_ts

DEFAULT_API_URL = "https://api.github.com"
NEW_ACCOUNT_DAYS = 30  # §5.3
# «Blobs base64 u ofuscados de más de N KB» (§5.3): el plan no fija N. Valor por defecto aquí,
# configurable (`blob_kb`); está en las preguntas abiertas del informe de T7.
DEFAULT_BLOB_KB = 8
DEFAULT_MAX_FILES = 12  # ficheros de texto leídos por repositorio
DEFAULT_MAX_FILE_BYTES = 256 * 1024

REASONS = ("binary", "blob", "curl_sh", "new_account", "readme_only", "fork")

BINARY_EXT = frozenset(
    {
        ".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".msi", ".scr", ".sys", ".o", ".a",
        ".obj", ".class", ".jar", ".war", ".ear", ".apk", ".ipa", ".deb", ".rpm", ".dmg", ".pkg",
        ".pyc", ".pyo", ".node", ".wasm", ".lnk", ".cab", ".iso", ".img",
        ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    }
)  # fmt: skip
CODE_EXT = frozenset(
    {
        ".py", ".rb", ".go", ".c", ".h", ".cc", ".cpp", ".hpp", ".rs", ".java", ".kt", ".scala",
        ".js", ".mjs", ".cjs", ".ts", ".php", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat",
        ".cmd", ".vbs", ".pl", ".pm", ".lua", ".cs", ".swift", ".m", ".r", ".nse", ".html",
        ".htm", ".xml", ".jsp", ".asp", ".aspx", ".groovy", ".yaml", ".yml", ".s", ".asm",
    }
)  # fmt: skip
CODE_NAMES = frozenset({"dockerfile", "makefile", "vagrantfile", "rakefile", "gemfile"})
DOC_EXT = frozenset({".md", ".txt", ".rst", ".markdown", ""})

# -- detectores sobre texto -----------------------------------------------------------------------

_PIPE_TO_SHELL = [
    re.compile(
        r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:/(?:usr/)?bin/)?"
        r"(?:ba|z|da|k|c|tc)?sh\b",
        re.I,
    ),
    re.compile(
        r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:python[0-9.]*|perl|ruby|php|node)\b", re.I
    ),
    re.compile(r"\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?(?:\$\(|<\()\s*(?:curl|wget)\b", re.I),
    re.compile(
        r"\b(?:iex|Invoke-Expression)\b[^\n]*"
        r"(?:DownloadString|\biwr\b|Invoke-WebRequest|\birm\b|Invoke-RestMethod)",
        re.I,
    ),
    re.compile(
        r"(?:DownloadString|\biwr\b|Invoke-WebRequest|\birm\b|Invoke-RestMethod)[^\n]*\|\s*"
        r"(?:iex|Invoke-Expression)\b",
        re.I,
    ),
]
# Comandos que descargan a disco. `curl` solo cuenta con -o/-O (si no, suele ser la petición al
# objetivo); `wget` y los demás, siempre.
_CURL = re.compile(r"\bcurl\b", re.I)
_CURL_SAVES = re.compile(r"\s(?:-[a-zA-Z]*[oO]\b|--output\b|--remote-name\b)")
_DOWNLOADER = re.compile(
    r"\b(?:wget|Invoke-WebRequest|iwr|Start-BitsTransfer|certutil|bitsadmin|urlretrieve"
    r"|DownloadFile)\b",
    re.I,
)
_URL = re.compile(r"https?://[^\s\"'<>)\]}]+", re.I)
_DECODE_EXEC = [
    re.compile(
        r"\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|codecs\.decode|zlib\.decompress)", re.I
    ),
    re.compile(r"\beval\s*\(\s*(?:atob|Buffer\.from)\s*\(", re.I),
    re.compile(r"\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(", re.I),
    re.compile(r"-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/]{40,}={0,2}", re.I),
    re.compile(r"\bbase64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:ba|z)?sh\b", re.I),
]
_B64_RUN = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_HEX_ESC_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
_HEX_LIST_RUN = re.compile(r"(?:0x[0-9a-fA-F]{1,2}\s*,\s*)+")
# Para unir un base64 partido en varias líneas o concatenado entre comillas.
_JOINERS = re.compile(r"[\"'\s+\\]")
_PLACEHOLDER_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".local")
_PLACEHOLDER_DOMAINS = ("example.com", "example.net", "example.org")


def _longest(pattern: re.Pattern[str], text: str) -> int:
    return max((len(m.group(0)) for m in pattern.finditer(text)), default=0)


def has_blob(text: str, blob_kb: int = DEFAULT_BLOB_KB) -> bool:
    """¿Hay un blob base64 u ofuscado de al menos `blob_kb` KB, o un «descodificar y ejecutar»?"""
    limit = blob_kb * 1024
    if any(p.search(text) for p in _DECODE_EXEC):
        return True
    if _longest(_HEX_ESC_RUN, text) >= limit or _longest(_HEX_LIST_RUN, text) >= limit:
        return True
    if _longest(_B64_RUN, text) >= limit:
        return True
    return _longest(_B64_RUN, _JOINERS.sub("", text)) >= limit


def _placeholder_host(host: str) -> bool:
    if host in ("localhost",) or "." not in host:
        return True
    if host.endswith(_PLACEHOLDER_SUFFIXES):
        return True
    if any(host == d or host.endswith("." + d) for d in _PLACEHOLDER_DOMAINS):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    # Una IP privada o de documentación es el «objetivo» de laboratorio; una pública no.
    return not ip.is_global


def _allowed(host: str, allowed: Iterable[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in allowed)


def foreign_downloads(text: str, allowed_domains: Iterable[str] = ()) -> list[str]:
    """Hosts de descargas a disco fuera de la lista permitida (sin los de ejemplo o laboratorio)."""
    allowed = [d.lower().strip(".") for d in allowed_domains]
    hosts: list[str] = []
    for line in text.splitlines():
        downloads = _DOWNLOADER.search(line) or (_CURL.search(line) and _CURL_SAVES.search(line))
        if not downloads:
            continue
        for url in _URL.findall(line):
            try:
                host = (urlsplit(url).hostname or "").lower()
            except ValueError:
                continue
            if (
                host
                and host not in hosts
                and not _placeholder_host(host)
                and not _allowed(host, allowed)
            ):
                hosts.append(host)
    return hosts


def has_pipe_to_shell(text: str) -> bool:
    return any(p.search(text) for p in _PIPE_TO_SHELL)


def _ext(path: str) -> str:
    name = PurePosixPath(path).name.lower()
    for double in (".tar.gz", ".tar.xz", ".tar.bz2"):
        if name.endswith(double):
            return ".tgz"
    return PurePosixPath(name).suffix


def is_binary_path(path: str) -> bool:
    return _ext(path) in BINARY_EXT


def is_code_path(path: str, mode: str | None = None) -> bool:
    name = PurePosixPath(path).name.lower()
    if name in CODE_NAMES or _ext(path) in CODE_EXT:
        return True
    # Sin extensión pero marcado como ejecutable en git (script con shebang).
    return mode == "100755" and _ext(path) == ""


def is_readme(path: str) -> bool:
    return PurePosixPath(path).name.lower().startswith("readme")


# -- hechos y veredicto ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RepoFile:
    path: str
    size: int
    mode: str | None = None


@dataclass
class RepoFacts:
    """Lo que se sabe de un repositorio sin clonarlo. `None` = no se ha podido leer."""

    full_name: str
    fork: bool | None = None
    repo_created_at: datetime | None = None
    owner_created_at: datetime | None = None
    files: list[RepoFile] | None = None
    tree_truncated: bool = False
    release_assets: list[str] | None = None
    texts: dict[str, str] = field(default_factory=dict)  # ruta → texto leído
    binary_texts: list[str] = field(default_factory=list)  # rutas leídas que no eran texto
    unread: list[str] = field(default_factory=list)  # ficheros que había que leer y no se leyeron
    errors: list[str] = field(default_factory=list)

    def complete(self) -> bool:
        return (
            self.fork is not None
            and self.repo_created_at is not None
            and self.owner_created_at is not None
            and self.files is not None
            and not self.tree_truncated
            and self.release_assets is not None
            and not self.unread
            and not self.errors
        )


@dataclass(frozen=True)
class PocVerdict:
    suspicious: bool | None
    reasons: tuple[str, ...] = ()
    inspected: bool = False
    detail: tuple[str, ...] = ()

    def to_value(self) -> dict[str, Any]:
        return {
            "suspicious": self.suspicious,
            "suspicious_reasons": list(self.reasons),
            "inspected": self.inspected,
        }


UNINSPECTED = PocVerdict(suspicious=None)


def evaluate(
    facts: RepoFacts,
    *,
    blob_kb: int = DEFAULT_BLOB_KB,
    allowed_download_domains: Iterable[str] = (),
) -> PocVerdict:
    """Aplica las seis heurísticas a los hechos. Determinista y sin red."""
    reasons: set[str] = set()
    detail: list[str] = []
    allowed = list(allowed_download_domains)

    if facts.fork:
        reasons.add("fork")
    if (
        facts.repo_created_at
        and facts.owner_created_at
        and facts.repo_created_at - facts.owner_created_at < timedelta(days=NEW_ACCOUNT_DAYS)
    ):
        reasons.add("new_account")
    for f in facts.files or []:
        if is_binary_path(f.path):
            reasons.add("binary")
            detail.append(f"binary:{f.path}")
    for a in facts.release_assets or []:
        if is_binary_path(a):
            reasons.add("binary")
            detail.append(f"release:{a}")
    if facts.binary_texts:
        reasons.add("binary")
        detail.extend(f"binary:{p}" for p in facts.binary_texts)
    if (
        facts.files is not None
        and not facts.tree_truncated
        and not any(is_code_path(f.path, f.mode) or is_binary_path(f.path) for f in facts.files)
    ):
        reasons.add("readme_only")
    for path, text in facts.texts.items():
        if has_blob(text, blob_kb):
            reasons.add("blob")
            detail.append(f"blob:{path}")
        if has_pipe_to_shell(text):
            reasons.add("curl_sh")
            detail.append(f"curl_sh:{path}")
        for host in foreign_downloads(text, allowed):
            reasons.add("curl_sh")
            detail.append(f"download:{host}")

    ordered = tuple(r for r in REASONS if r in reasons)
    if ordered:
        return PocVerdict(True, ordered, inspected=True, detail=tuple(detail))
    if facts.complete():
        return PocVerdict(False, (), inspected=True)
    return PocVerdict(None, (), inspected=False, detail=tuple(facts.errors + facts.unread))


# -- lector por la API de GitHub ------------------------------------------------------------------


def _decode_content(payload: Any, url: str) -> bytes:
    if not isinstance(payload, dict) or payload.get("encoding") != "base64":
        raise SourceError(f"contenido sin base64 en {url}")
    try:
        return base64.b64decode(str(payload.get("content") or ""), validate=False)
    except (binascii.Error, ValueError) as exc:
        raise SourceError(f"base64 no válido en {url}: {exc}") from exc


class PocInspector:
    """Reúne `RepoFacts` con la API de GitHub (solo GET bajo `api_url`) y da el veredicto.

    Presupuesto por ejecución: `max_inspections` repositorios. Fuera de presupuesto, o si la API
    falla, el repositorio queda sin inspeccionar (`suspicious = None`): nunca «limpio».
    """

    def __init__(
        self,
        transport: Transport,
        *,
        headers: Mapping[str, str] | None = None,
        api_url: str = DEFAULT_API_URL,
        max_inspections: int = 50,
        max_files: int = DEFAULT_MAX_FILES,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        blob_kb: int = DEFAULT_BLOB_KB,
        allowed_download_domains: Iterable[str] = (),
        on_request: Callable[[], None] | None = None,
    ) -> None:
        self.transport = transport
        self.headers = dict(headers or {})
        self.api_url = api_url.rstrip("/")
        self.max_inspections = max_inspections
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.blob_kb = blob_kb
        self.allowed = tuple(allowed_download_domains)
        self.on_request = on_request
        self.used = 0
        self.stats: dict[str, int] = {}

    def _count(self, stat: str) -> None:
        self.stats[stat] = self.stats.get(stat, 0) + 1

    def _get(self, path: str) -> Any:
        url = f"{self.api_url}/{path}"
        if self.on_request:
            self.on_request()
        return parse_json(get_ok(self.transport, url, headers=self.headers).body, url)

    def facts(
        self,
        full_name: str,
        *,
        owner: str,
        fork: bool | None = None,
        repo_created_at: datetime | None = None,
    ) -> RepoFacts:
        facts = RepoFacts(full_name=full_name, fork=fork, repo_created_at=repo_created_at)
        repo_path = "repos/" + "/".join(quote(p, safe="") for p in full_name.split("/", 1))
        steps: list[tuple[str, Callable[[], None]]] = []

        def repo() -> None:
            data = self._get(repo_path)
            if not isinstance(data, dict):
                raise SourceError("repositorio que no es un objeto")
            facts.fork = bool(data.get("fork"))
            facts.repo_created_at = parse_ts(data.get("created_at"), f"{full_name} created_at")

        def user() -> None:
            data = self._get(f"users/{quote(owner, safe='')}")
            if not isinstance(data, dict):
                raise SourceError("usuario que no es un objeto")
            facts.owner_created_at = parse_ts(data.get("created_at"), f"{owner} created_at")

        def tree() -> None:
            data = self._get(f"{repo_path}/git/trees/HEAD?recursive=1")
            if not isinstance(data, dict) or not isinstance(data.get("tree"), list):
                raise SourceError("árbol sin 'tree'")
            facts.tree_truncated = bool(data.get("truncated"))
            facts.files = [
                RepoFile(str(e.get("path")), int(e.get("size") or 0), e.get("mode"))
                for e in data["tree"]
                if isinstance(e, dict) and e.get("type") == "blob" and e.get("path")
            ]

        def releases() -> None:
            data = self._get(f"{repo_path}/releases?per_page=20")
            if not isinstance(data, list):
                raise SourceError("releases que no son una lista")
            facts.release_assets = [
                str(a.get("name"))
                for r in data
                if isinstance(r, dict)
                for a in r.get("assets") or []
                if isinstance(a, dict) and a.get("name")
            ]

        if fork is None or repo_created_at is None:
            steps.append(("repo", repo))
        steps += [("user", user), ("tree", tree), ("releases", releases)]
        for what, step in steps:
            try:
                step()
            except SourceError as exc:
                facts.errors.append(f"{what}: {exc}"[:200])
        self._read_texts(facts, repo_path)
        return facts

    def _read_texts(self, facts: RepoFacts, repo_path: str) -> None:
        if facts.files is None:
            return
        wanted = [
            f
            for f in facts.files
            if not is_binary_path(f.path)
            and (is_code_path(f.path, f.mode) or is_readme(f.path) or _ext(f.path) in DOC_EXT)
        ]
        for i, f in enumerate(wanted):
            if i >= self.max_files or f.size > self.max_file_bytes:
                facts.unread.append(f.path)
                continue
            path = "/".join(quote(p, safe="") for p in f.path.split("/"))
            try:
                body = _decode_content(self._get(f"{repo_path}/contents/{path}?ref=HEAD"), path)
            except SourceError as exc:
                facts.errors.append(f"contents {f.path}: {exc}"[:200])
                continue
            if b"\x00" in body:
                facts.binary_texts.append(f.path)
                continue
            facts.texts[f.path] = body.decode("utf-8", errors="replace")

    def inspect(
        self,
        full_name: str,
        *,
        owner: str,
        fork: bool | None = None,
        repo_created_at: datetime | None = None,
    ) -> PocVerdict:
        if self.used >= self.max_inspections:
            self._count("sin_presupuesto")
            return UNINSPECTED
        self.used += 1
        facts = self.facts(full_name, owner=owner, fork=fork, repo_created_at=repo_created_at)
        verdict = evaluate(facts, blob_kb=self.blob_kb, allowed_download_domains=self.allowed)
        self._count(
            "sospechosos"
            if verdict.suspicious
            else ("limpios" if verdict.suspicious is False else "incompletos")
        )
        return verdict
