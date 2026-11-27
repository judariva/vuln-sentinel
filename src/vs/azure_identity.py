"""Token de Entra ID de la identidad gestionada del componente, sin SDK de Azure (F1a).

En Container Apps, el entorno expone un endpoint local de identidad (`IDENTITY_ENDPOINT`) y una
cabecera secreta (`IDENTITY_HEADER`) que solo conoce el contenedor. Con una identidad asignada por
el usuario hay que pedir el token con su `client_id` (`AZURE_CLIENT_ID`, lo pone el módulo de
Terraform). Referencia: learn.microsoft.com/azure/container-apps/managed-identity, apartado
"Connect to Azure services in app code" → REST endpoint (api-version 2019-08-01).

- Nada se guarda en disco ni en logs: ni el token ni la cabecera.
- El token se reutiliza hasta 5 minutos antes de que caduque.
- Solo se admite el endpoint local por HTTP (`localhost` o `127.0.0.1`) o uno HTTPS.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

API_VERSION = "2019-08-01"
REFRESH_MARGIN = 300  # segundos antes de caducar en los que se pide un token nuevo
TIMEOUT = 10.0

# Recursos de Entra que usa el producto (el `scope` OAuth es el recurso + `/.default`).
POSTGRES_SCOPE = "https://ossrdbms-aad.database.windows.net/.default"
KEY_VAULT_SCOPE = "https://vault.azure.net/.default"


class IdentityError(RuntimeError):
    """No se pudo obtener el token. El mensaje nunca lleva el token ni la cabecera."""


class GetTransport(Protocol):
    def get(self, url: str, *, headers: Mapping[str, str], timeout: float) -> tuple[int, bytes]:
        """GET; devuelve (código HTTP, cuerpo). Error de red: `OSError`."""
        ...


class UrllibGetTransport:
    def get(self, url: str, *, headers: Mapping[str, str], timeout: float) -> tuple[int, bytes]:
        req = urllib.request.Request(url, headers=dict(headers), method="GET")  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - URL validada
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, b""


def scope_to_resource(scope: str) -> str:
    """`https://x/.default` → `https://x`: el endpoint de identidad pide el recurso, no el scope."""
    resource = scope.removesuffix("/.default")
    if not resource.startswith("https://") or resource == "https://":
        raise ValueError(f"scope no válido: {scope}")
    return resource


def _check_endpoint(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    local = parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1")
    if not (local or parts.scheme == "https") or not parts.hostname:
        raise IdentityError("IDENTITY_ENDPOINT no es local ni HTTPS")
    return url


@dataclass
class _Cached:
    token: str
    expires_on: float


class ManagedIdentityCredential:
    """Token de la identidad gestionada asignada por el usuario (`client_id`)."""

    def __init__(
        self,
        client_id: str,
        *,
        endpoint: str,
        header: str,
        transport: GetTransport | None = None,
        clock: Callable[[], float] = time.time,
        timeout: float = TIMEOUT,
    ) -> None:
        if not client_id:
            raise ValueError("client_id vacío")
        if not header:
            raise IdentityError("falta IDENTITY_HEADER")
        self.client_id = client_id
        self._endpoint = _check_endpoint(endpoint)
        self._header = header
        self.transport = transport or UrllibGetTransport()
        self.clock = clock
        self.timeout = timeout
        self._cache: dict[str, _Cached] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **kwargs) -> ManagedIdentityCredential:
        env = os.environ if env is None else env
        endpoint = env.get("IDENTITY_ENDPOINT", "")
        if not endpoint:
            raise IdentityError("falta IDENTITY_ENDPOINT: no hay identidad gestionada")
        return cls(
            env.get("AZURE_CLIENT_ID", ""),
            endpoint=endpoint,
            header=env.get("IDENTITY_HEADER", ""),
            **kwargs,
        )

    def token(self, scope: str) -> str:
        resource = scope_to_resource(scope)
        with self._lock:
            cached = self._cache.get(resource)
            if cached and cached.expires_on - REFRESH_MARGIN > self.clock():
                return cached.token
            fresh = self._fetch(resource)
            self._cache[resource] = fresh
            return fresh.token

    def _fetch(self, resource: str) -> _Cached:
        query = urllib.parse.urlencode(
            {"api-version": API_VERSION, "resource": resource, "client_id": self.client_id}
        )
        sep = "&" if "?" in self._endpoint else "?"
        try:
            status, body = self.transport.get(
                f"{self._endpoint}{sep}{query}",
                headers={"X-IDENTITY-HEADER": self._header},
                timeout=self.timeout,
            )
        except OSError as exc:
            raise IdentityError(
                f"error de red con el endpoint de identidad ({type(exc).__name__})"
            ) from None
        if status != 200:
            raise IdentityError(f"el endpoint de identidad respondió HTTP {status}")
        try:
            doc = json.loads(body)
            token = str(doc["access_token"])
            expires_on = float(doc["expires_on"])
        except (ValueError, KeyError, TypeError) as exc:
            raise IdentityError(
                f"respuesta de identidad no válida ({type(exc).__name__})"
            ) from None
        if not token:
            raise IdentityError("respuesta de identidad sin token")
        return _Cached(token, expires_on)


def in_azure(env: Mapping[str, str] | None = None) -> bool:
    """True si el proceso corre con identidad gestionada (Container Apps)."""
    env = os.environ if env is None else env
    return bool(env.get("IDENTITY_ENDPOINT"))
