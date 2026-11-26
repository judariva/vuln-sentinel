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
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

DEFAULT_TIMEOUT_S = 30.0
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF_S = (1.0, 4.0)
RETRY_STATUS = frozenset({502, 503, 504})
# Genérico a propósito: sin hosts ni datos de contacto (ADR-0016).
USER_AGENT = "vuln-sentinel"


class SourceError(RuntimeError):
    """La fuente no ha dado un dato utilizable. Lleva a UNKNOWN."""


class NetworkError(SourceError):
    """Timeout o fallo de conexión o de TLS. Se reintenta un número acotado de veces."""


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
    """GET por HTTPS con timeout y tamaño máximo. Sin redirecciones a otros esquemas.

    Un 502, 503 o 504, un timeout o un fallo de conexión o de TLS se reintentan como mucho
    `retries` veces, con espera creciente (T13): la carga inicial de cvelistV5 u OSV son miles de
    GET, y un 503 o un timeout suelto la dejaba entera en UNKNOWN. Un certificado no válido se
    reintenta igual y sigue fallando: la verificación nunca se relaja.
    Si persiste, se devuelve tal cual y el conector da UNKNOWN. Un 429 o un 403 no se reintentan:
    son límites de uso y reintentar solo los empeora.
    """

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        max_bytes: int = DEFAULT_MAX_BYTES,
        retries: int = DEFAULT_RETRIES,
        backoff: tuple[float, ...] = DEFAULT_BACKOFF_S,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.retries = retries
        self.backoff = backoff
        self._sleep = sleep

    def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, timeout: float | None = None
    ) -> Response:
        attempt = 0
        while True:
            try:
                resp = self._get_once(url, headers=headers, timeout=timeout)
            except NetworkError:
                if attempt >= self.retries:
                    raise
            else:
                if resp.status not in RETRY_STATUS or attempt >= self.retries:
                    return resp
            self._sleep(self.backoff[min(attempt, len(self.backoff) - 1)])
            attempt += 1

    def _get_once(
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
            raise NetworkError(f"error de red en {url}: {exc}") from exc
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
