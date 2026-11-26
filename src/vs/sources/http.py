"""Transporte HTTP de los conectores y errores de fuente.

Los conectores no llaman a la red directamente: piden a un `Transport`. En producción es
`UrllibTransport` (solo GET y solo HTTPS); en los tests, un transporte simulado que sirve fixtures.
Así ningún test hace una llamada de red real.

Cualquier error aquí (timeout, HTTP distinto de 2xx, JSON roto, cuerpo demasiado grande) es una
`SourceError`: el ejecutor (`vs.sources.run`) la convierte en UNKNOWN, nunca en «sin novedades».
"""

from __future__ import annotations

import gzip
import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

DEFAULT_TIMEOUT_S = 30.0
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
# Genérico a propósito: sin hosts ni datos de contacto (ADR-0016).
USER_AGENT = "vuln-sentinel"


class SourceError(RuntimeError):
    """La fuente no ha dado un dato utilizable. Lleva a UNKNOWN."""


class SourceStale(SourceError):
    """El dato de la fuente es más viejo que el umbral."""


class SourceIncomplete(SourceError):
    """No se ha podido leer todo lo nuevo desde el cursor (ventana o páginas insuficientes)."""


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return None


class Transport(Protocol):
    def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, timeout: float = ...
    ) -> Response: ...


class UrllibTransport:
    """GET por HTTPS con timeout y tamaño máximo. Sin redirecciones a otros esquemas."""

    def __init__(
        self, *, timeout: float = DEFAULT_TIMEOUT_S, max_bytes: int = DEFAULT_MAX_BYTES
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes

    def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, timeout: float | None = None
    ) -> Response:
        if not url.startswith("https://"):
            raise SourceError(f"solo se admite HTTPS: {url}")
        req = urllib.request.Request(  # noqa: S310 - esquema comprobado arriba
            url, headers={"User-Agent": USER_AGENT, **dict(headers or {})}, method="GET"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:  # noqa: S310
                body = resp.read(self.max_bytes + 1)
                status = resp.status
                hdrs = dict(resp.headers.items())
        except urllib.error.HTTPError as exc:
            return Response(exc.code, exc.read(self.max_bytes + 1), dict(exc.headers.items()))
        except (TimeoutError, urllib.error.URLError, OSError) as exc:
            raise SourceError(f"error de red en {url}: {exc}") from exc
        if len(body) > self.max_bytes:
            raise SourceError(f"respuesta de más de {self.max_bytes} bytes: {url}")
        return Response(status, body, hdrs)


# -- ayudas para los conectores -----------------------------------------------------------------


def get_ok(
    transport: Transport,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
    accept: tuple[int, ...] = (200,),
) -> Response:
    """GET que exige un estado admitido. El timeout del transporte también es `SourceError`."""
    try:
        resp = transport.get(url, headers=headers, timeout=timeout)
    except SourceError:
        raise
    except TimeoutError as exc:
        raise SourceError(f"timeout en {url}") from exc
    except OSError as exc:
        raise SourceError(f"error de red en {url}: {exc}") from exc
    if resp.status not in accept:
        raise SourceError(f"HTTP {resp.status} en {url}")
    return resp


def parse_json(body: bytes, url: str) -> Any:
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceError(f"JSON no válido en {url}: {exc}") from exc


def get_json(transport: Transport, url: str, **kwargs: Any) -> Any:
    return parse_json(get_ok(transport, url, **kwargs).body, url)


def maybe_gunzip(body: bytes, url: str) -> bytes:
    if body[:2] != b"\x1f\x8b":
        return body
    try:
        return gzip.decompress(body)
    except (OSError, EOFError) as exc:
        raise SourceError(f"gzip no válido en {url}: {exc}") from exc


def parse_ts(value: Any, what: str) -> datetime:
    """Fecha ISO 8601 a `datetime` con zona (UTC si no la trae). Error de fuente si no vale."""
    if not isinstance(value, str) or not value:
        raise SourceError(f"{what}: fecha ausente o no válida: {value!r}")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # OSV da nanosegundos; `fromisoformat` admite como mucho microsegundos.
    if "." in text:
        head, _, rest = text.partition(".")
        digits = "".join(c for c in rest if c.isdigit())
        tz = rest[len(digits) :]
        text = f"{head}.{digits[:6]}{tz}"
    try:
        ts = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SourceError(f"{what}: fecha no válida: {value!r}") from exc
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)
