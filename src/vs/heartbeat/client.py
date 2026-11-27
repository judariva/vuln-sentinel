"""Cliente del latido: interfaz simulable y cliente de la Logs Ingestion API.

`LogsIngestionClient` construye la petición documentada en
https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview (leída el
2026-11-26; `updated_at` 2026-11-19):

- «`{endpoint}/dataCollectionRules/{dcrImmutableId}/streams/{streamName}?api-version={apiVersion}`»;
- cabeceras `Authorization` («Bearer token for the identity that authenticates the call») y
  `Content-Type: application/json`;
- cuerpo: «The data must be a JSON array with an item structure that matches the format expected
  by the stream in the DCR», en UTF-8;
- audiencia del token en la nube pública: `https://monitor.azure.com` (scope `…/.default`).

SIN VERIFICAR (la página usa el marcador `{apiVersion}` sin valor): la versión `2023-01-01` de la
API de subida y el tamaño máximo por llamada. Se comprueban en la F1a con el primer envío real.

La autenticación real es la identidad gestionada del job (`ManagedIdentityTokenProvider`, que usa
`vs.azure_identity`): el endpoint local de identidad de Container Apps, sin ningún SDK.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

from vs.azure_identity import ManagedIdentityCredential

DEFAULT_API_VERSION = "2023-01-01"  # SIN VERIFICAR (ver docstring)
MONITOR_SCOPE = "https://monitor.azure.com/.default"
DEFAULT_TIMEOUT_S = 10.0
MAX_BODY_BYTES = 1024 * 1024  # muy por encima de una fila de latido; el límite real, SIN VERIFICAR
DCR_ID_RE = re.compile(r"dcr-[0-9a-f]{32}")
STREAM_RE = re.compile(r"Custom-[A-Za-z0-9_]{1,100}")


class HeartbeatError(RuntimeError):
    """El latido no se ha podido enviar."""


class HeartbeatClient(ABC):
    @abstractmethod
    def send(self, rows: Sequence[Mapping[str, Any]]) -> None:
        """Envía las filas. Si no se pudieron enviar, `HeartbeatError`."""


class FakeHeartbeatClient(HeartbeatClient):
    """Cliente simulado para tests y para ejecutar los jobs en local."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.rows: list[dict[str, Any]] = []

    def send(self, rows: Sequence[Mapping[str, Any]]) -> None:
        if self.fail:
            raise HeartbeatError("fallo simulado")
        self.rows.extend(dict(r) for r in rows)


# -- autenticación y transporte -----------------------------------------------------------------


class TokenProvider(Protocol):
    def token(self, scope: str) -> str:
        """Token de acceso de Entra ID para el scope dado."""
        ...


class ManagedIdentityTokenProvider:
    """Token de la identidad gestionada del job (asignada por el usuario, CMP-026).

    Lo pide al endpoint de identidad de Container Apps con el `client_id` de la identidad del job
    (`vs.azure_identity.ManagedIdentityCredential`). No hay secretos que guardar.
    """

    def __init__(self, client_id: str, env: Mapping[str, str] | None = None, **kwargs: Any) -> None:
        if not client_id:
            raise ValueError("client_id vacío")
        self.client_id = client_id
        self._env = env
        self._kwargs = kwargs
        self._credential: ManagedIdentityCredential | None = None

    def token(self, scope: str) -> str:
        if self._credential is None:
            env = dict(os.environ if self._env is None else self._env)
            env["AZURE_CLIENT_ID"] = self.client_id
            self._credential = ManagedIdentityCredential.from_env(env, **self._kwargs)
        return self._credential.token(scope)


class PostTransport(Protocol):
    def post(self, url: str, *, headers: Mapping[str, str], body: bytes, timeout: float) -> int:
        """POST; devuelve el código HTTP. Error de red: `OSError`."""
        ...


class UrllibPostTransport:
    """POST por HTTPS con timeout. Sin cuerpo de respuesta: el latido solo mira el código."""

    def post(self, url: str, *, headers: Mapping[str, str], body: bytes, timeout: float) -> int:
        if not url.startswith("https://"):
            raise HeartbeatError("solo se admite HTTPS")
        req = urllib.request.Request(  # noqa: S310 - esquema comprobado arriba
            url, data=body, headers=dict(headers), method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code


# -- cliente real -------------------------------------------------------------------------------


class LogsIngestionClient(HeartbeatClient):
    """Envío a la Logs Ingestion API (DCR `Direct`, tabla `VsHeartbeat_CL`).

    Los tres valores salen de la DCR que crea la plataforma y llegan por la variable `heartbeat` del
    módulo Terraform (`VS_HEARTBEAT_ENDPOINT`, `VS_HEARTBEAT_DCR_ID` y `VS_HEARTBEAT_STREAM`), nunca
    del código.
    """

    def __init__(
        self,
        endpoint: str,
        dcr_immutable_id: str,
        stream_name: str,
        tokens: TokenProvider,
        transport: PostTransport | None = None,
        *,
        api_version: str = DEFAULT_API_VERSION,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme != "https" or not parts.netloc or parts.query or parts.fragment:
            raise ValueError("endpoint debe ser una URL https sin query")
        if not DCR_ID_RE.fullmatch(dcr_immutable_id):
            raise ValueError("dcr_immutable_id no válido")
        if not STREAM_RE.fullmatch(stream_name):
            raise ValueError("stream_name no válido")
        self.endpoint = endpoint.rstrip("/")
        self.dcr_immutable_id = dcr_immutable_id
        self.stream_name = stream_name
        self.tokens = tokens
        self.transport = transport or UrllibPostTransport()
        self.api_version = api_version
        self.timeout = timeout

    @property
    def url(self) -> str:
        return (
            f"{self.endpoint}/dataCollectionRules/{quote(self.dcr_immutable_id)}"
            f"/streams/{quote(self.stream_name)}?api-version={quote(self.api_version)}"
        )

    def send(self, rows: Sequence[Mapping[str, Any]]) -> None:
        if not rows:
            return
        body = json.dumps(list(rows), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_BODY_BYTES:
            raise HeartbeatError(f"latido de {len(body)} bytes; máximo {MAX_BODY_BYTES}")
        try:
            token = self.tokens.token(MONITOR_SCOPE)
        except NotImplementedError:
            raise
        except Exception as exc:
            # Sin el texto de la excepción: podría llevar detalles de la identidad.
            raise HeartbeatError(f"no se pudo obtener el token ({type(exc).__name__})") from exc
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        try:
            status = self.transport.post(self.url, headers=headers, body=body, timeout=self.timeout)
        except (OSError, HeartbeatError) as exc:
            raise HeartbeatError(
                f"error de red al enviar el latido ({type(exc).__name__})"
            ) from exc
        if not 200 <= status < 300:
            raise HeartbeatError(f"la Logs Ingestion API respondió HTTP {status}")
