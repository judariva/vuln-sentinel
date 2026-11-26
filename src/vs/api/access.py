"""Validación del JWT de Cloudflare Access para `/admin/*` (PLAN.md §10).

Access pone el JWT en la cabecera `Cf-Access-Jwt-Assertion`. El origen no confía solo en que el
Tunnel y Access estén delante: valida la firma (RS256) con las claves públicas del equipo, el emisor
(`iss`), la audiencia (`aud`, la etiqueta AUD de la aplicación) y la vigencia (`exp`, `nbf`).

Fail-closed: sin configuración (`team_domain` y `audience`), toda petición a `/admin/*` se rechaza.
Ni el dominio del equipo ni la AUD van en el código: salen de la configuración (ADR-0016).
"""

from __future__ import annotations

import json
import time
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from vs.feed.sign import b64url_decode

HEADER = "Cf-Access-Jwt-Assertion"
CERTS_PATH = "/cdn-cgi/access/certs"
ALG = "RS256"
LEEWAY_SECONDS = 60
JWKS_TTL_SECONDS = 3600


class AccessError(Exception):
    """El JWT de Access falta (401) o no es válido (403)."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass(frozen=True)
class AccessConfig:
    """`team_domain`: `https://<equipo>.cloudflareaccess.com`. `audience`: etiqueta AUD."""

    team_domain: str | None = None
    audience: str | None = None

    @property
    def configured(self) -> bool:
        return bool(self.team_domain and self.audience)

    def __post_init__(self) -> None:
        if self.team_domain is not None:
            parts = urlsplit(self.team_domain)
            if parts.scheme != "https" or not parts.netloc or parts.path not in ("", "/"):
                raise ValueError(f"team_domain debe ser https://<host>: {self.team_domain!r}")
            object.__setattr__(self, "team_domain", self.team_domain.rstrip("/"))


JwksProvider = Callable[[], Mapping[str, Any]]


def _b64json(part: str) -> dict[str, Any]:
    try:
        value = json.loads(b64url_decode(part))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AccessError(403, "JWT mal formado") from exc
    if not isinstance(value, dict):
        raise AccessError(403, "JWT mal formado")
    return value


def _rsa_key(jwk: Mapping[str, Any]) -> rsa.RSAPublicKey:
    if jwk.get("kty") != "RSA":
        raise AccessError(403, "clave del JWKS no es RSA")
    n = int.from_bytes(b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


@dataclass
class AccessVerifier:
    """Valida el JWT de Access. `jwks` devuelve el JWKS del equipo (en tests, uno fijo)."""

    config: AccessConfig
    jwks: JwksProvider | None = None
    clock: Callable[[], float] = time.time
    _cache: tuple[float, Mapping[str, Any]] | None = field(default=None, init=False, repr=False)

    def _keys(self) -> Mapping[str, Any]:
        if self.jwks is not None:
            return self.jwks()
        now = self.clock()
        if self._cache is None or now - self._cache[0] > JWKS_TTL_SECONDS:
            self._cache = (now, fetch_jwks(self.config))
        return self._cache[1]

    def verify(self, token: str | None) -> dict[str, Any]:
        """Devuelve los claims si el JWT es válido. Lanza `AccessError` si no."""
        if not self.config.configured:
            raise AccessError(403, "Access no está configurado: /admin cerrado")
        if not token:
            raise AccessError(401, f"falta la cabecera {HEADER}")
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise AccessError(403, "JWT mal formado")
        header, claims = _b64json(parts[0]), _b64json(parts[1])
        if header.get("alg") != ALG:
            raise AccessError(403, "algoritmo del JWT no admitido")
        kid = header.get("kid")
        keys = [k for k in self._keys().get("keys", []) if k.get("kid") == kid]
        if not kid or len(keys) != 1:
            raise AccessError(403, "kid del JWT desconocido")
        try:
            signature = b64url_decode(parts[2])
            _rsa_key(keys[0]).verify(
                signature,
                f"{parts[0]}.{parts[1]}".encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except (InvalidSignature, ValueError, KeyError) as exc:
            raise AccessError(403, "firma del JWT no válida") from exc
        self._check_claims(claims)
        return claims

    def _check_claims(self, claims: Mapping[str, Any]) -> None:
        if claims.get("iss") != self.config.team_domain:
            raise AccessError(403, "emisor del JWT no válido")
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if self.config.audience not in auds:
            raise AccessError(403, "audiencia del JWT no válida")
        now = self.clock()
        exp, nbf = claims.get("exp"), claims.get("nbf")
        if not isinstance(exp, int | float) or now > exp + LEEWAY_SECONDS:
            raise AccessError(403, "JWT caducado")
        if nbf is not None and (not isinstance(nbf, int | float) or now + LEEWAY_SECONDS < nbf):
            raise AccessError(403, "JWT aún no válido")


def fetch_jwks(config: AccessConfig) -> Mapping[str, Any]:
    """Claves públicas del equipo de Access. Solo https y solo el dominio configurado."""
    if not config.configured:
        raise AccessError(403, "Access no está configurado")
    url = f"{config.team_domain}{CERTS_PATH}"
    if urlsplit(url).scheme != "https":  # pragma: no cover - lo impide AccessConfig
        raise AccessError(403, "URL de claves no https")
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310 - https comprobado
            data = json.loads(resp.read())
    except (OSError, ValueError) as exc:
        raise AccessError(403, "no se pudieron leer las claves de Access") from exc
    if not isinstance(data, dict):
        raise AccessError(403, "JWKS de Access no válido")
    return data
