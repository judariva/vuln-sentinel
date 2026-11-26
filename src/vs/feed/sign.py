"""Firma del feed: JWS detached ES256 sobre los bytes exactos (RFC 7797, ADR-0008).

Formato: JWS compacto con el payload separado, `<cabecera>..<firma>`. La cabecera protegida es
`{"alg":"ES256","b64":false,"crit":["b64"],"kid":…}` y la entrada firmada es
`ASCII(BASE64URL(cabecera)) || "." || bytes del documento` (RFC 7797, §3). La firma ES256 es
`r || s`, 64 bytes (RFC 7518, §3.4).

La firma va detrás de la interfaz `Signer`:

- `LocalDevSigner`: clave P-256 en memoria, generada en el test o leída de `.cache/`. Nunca en git.
- `KeyVaultSigner`: la clave no exportable de Key Vault (CMP-008). Aquí solo está la interfaz; la
  llamada a Azure se escribe en la F1a.

Cualquiera puede verificar con `openssl` o con una librería JOSE (`examples/verify/`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

ALG = "ES256"
_COORD = 32  # bytes de cada coordenada y de r y s en P-256


class SignatureError(ValueError):
    """La firma no es válida o no se puede comprobar."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise SignatureError(f"base64url no válido: {exc}") from exc


def _int_b64(value: int) -> str:
    return b64url(value.to_bytes(_COORD, "big"))


# -- firmantes -----------------------------------------------------------------------------------


class Signer(ABC):
    """Firma ES256. Las implementaciones solo firman un resumen SHA-256 (como Key Vault)."""

    alg = ALG

    @property
    @abstractmethod
    def kid(self) -> str:
        """Identificador de la clave (`kid` del JWKS). Rota con la clave."""

    @abstractmethod
    def sign_digest(self, digest: bytes) -> bytes:
        """Firma un resumen SHA-256 de 32 bytes. Devuelve `r || s` (64 bytes)."""

    @abstractmethod
    def public_jwk(self) -> dict[str, str]:
        """Clave pública en formato JWK (RFC 7517), sin ningún parámetro privado."""

    def sign(self, data: bytes) -> bytes:
        sig = self.sign_digest(hashlib.sha256(data).digest())
        if len(sig) != 2 * _COORD:
            raise SignatureError(f"firma ES256 de {len(sig)} bytes; se esperaban 64")
        return sig


def _jwk(public: ec.EllipticCurvePublicKey, kid: str) -> dict[str, str]:
    nums = public.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_b64(nums.x),
        "y": _int_b64(nums.y),
        "kid": kid,
        "use": "sig",
        "alg": ALG,
    }


class LocalDevSigner(Signer):
    """Firmante de desarrollo con la clave en memoria. Solo para tests y pruebas locales.

    `generate()` crea una clave efímera. `load_or_create()` la guarda en un fichero que tiene que
    estar fuera del repo o bajo `.cache/` (ignorado por git): una clave de firma nunca va a git.
    """

    def __init__(self, key: ec.EllipticCurvePrivateKey, kid: str) -> None:
        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("ES256 exige una clave P-256")
        if not kid:
            raise ValueError("kid vacío")
        self._key = key
        self._kid = kid

    @classmethod
    def generate(cls, kid: str) -> LocalDevSigner:
        return cls(ec.generate_private_key(ec.SECP256R1()), kid)

    @classmethod
    def load_or_create(cls, path: str | Path, kid: str) -> LocalDevSigner:
        path = Path(path).resolve()
        _check_key_path(path)
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise ValueError(f"{path} no es una clave EC")
            return cls(key, kid)
        signer = cls.generate(kid)
        path.parent.mkdir(parents=True, exist_ok=True)
        pem = signer._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        return signer

    @property
    def kid(self) -> str:
        return self._kid

    def sign_digest(self, digest: bytes) -> bytes:
        if len(digest) != hashlib.sha256().digest_size:
            raise ValueError("sign_digest espera un resumen SHA-256")
        der = self._key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(_COORD, "big") + s.to_bytes(_COORD, "big")

    def public_jwk(self) -> dict[str, str]:
        return _jwk(self._key.public_key(), self._kid)

    def public_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )


def _repo_root(start: Path) -> Path | None:
    for parent in (start, *start.parents):
        if (parent / ".git").exists():
            return parent
    return None


def _check_key_path(path: Path) -> None:
    """Una clave dentro de un repo solo puede vivir bajo `.cache/` (ignorado por git)."""
    root = _repo_root(path.parent)
    if root is not None and not path.is_relative_to(root / ".cache"):
        raise ValueError(f"una clave de firma dentro del repo solo puede ir en .cache/: {path}")


class KeyVaultSigner(Signer):
    """Firma con la clave ES256 no exportable de Azure Key Vault (ADR-0008, CMP-008).

    Solo la interfaz. En la F1a, `sign_digest` llamará a la operación `sign` de Key Vault
    (algoritmo `ES256`, con la identidad administrada del job) y `public_jwk` leerá la parte
    pública de la clave. Esta clase no importa ningún SDK de Azure ni hace llamadas de red.
    """

    def __init__(self, vault_url: str, key_name: str, key_version: str, kid: str) -> None:
        self.vault_url = vault_url
        self.key_name = key_name
        self.key_version = key_version
        self._kid = kid

    @property
    def kid(self) -> str:
        return self._kid

    def sign_digest(self, digest: bytes) -> bytes:
        raise NotImplementedError("KeyVaultSigner.sign_digest: se implementa en la F1a")

    def public_jwk(self) -> dict[str, str]:
        raise NotImplementedError("KeyVaultSigner.public_jwk: se implementa en la F1a")


# -- JWS detached --------------------------------------------------------------------------------


def _header(kid: str) -> dict[str, Any]:
    return {"alg": ALG, "b64": False, "crit": ["b64"], "kid": kid}


def _compact_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_detached(payload: bytes, signer: Signer) -> str:
    """JWS compacto con payload separado: `<cabecera>..<firma>` (RFC 7797)."""
    protected = b64url(_compact_json(_header(signer.kid)))
    signature = signer.sign(protected.encode("ascii") + b"." + payload)
    return f"{protected}..{b64url(signature)}"


def _public_key(jwk: Mapping[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise SignatureError("la clave no es EC P-256")
    if any(k in jwk for k in ("d", "p", "q")):
        raise SignatureError("el JWKS contiene material privado")
    x = int.from_bytes(b64url_decode(str(jwk.get("x", ""))), "big")
    y = int.from_bytes(b64url_decode(str(jwk.get("y", ""))), "big")
    try:
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError as exc:
        raise SignatureError(f"punto no válido en P-256: {exc}") from exc


def parse_detached(jws: str) -> tuple[str, dict[str, Any], bytes]:
    """Devuelve (cabecera en base64url, cabecera, firma). Exige payload separado y ES256."""
    parts = jws.strip().split(".")
    if len(parts) != 3 or parts[1] != "":
        raise SignatureError("no es un JWS compacto con payload separado")
    protected, _, sig_b64 = parts
    try:
        header = json.loads(b64url_decode(protected))
    except json.JSONDecodeError as exc:
        raise SignatureError("cabecera protegida no es JSON") from exc
    if not isinstance(header, dict):
        raise SignatureError("cabecera protegida no es un objeto")
    if header.get("alg") != ALG:
        raise SignatureError(f"alg no admitido: {header.get('alg')!r}")
    if header.get("b64") is not False or header.get("crit") != ["b64"]:
        raise SignatureError("se exige b64=false con crit=['b64'] (RFC 7797)")
    signature = b64url_decode(sig_b64)
    if len(signature) != 2 * _COORD:
        raise SignatureError("firma ES256 de longitud incorrecta")
    return protected, header, signature


def verify_detached(jws: str, payload: bytes, jwks: Mapping[str, Any]) -> str:
    """Comprueba la firma sobre los bytes dados. Devuelve el `kid`; si no vale, `SignatureError`."""
    protected, header, signature = parse_detached(jws)
    kid = header.get("kid")
    keys = [k for k in jwks.get("keys") or [] if k.get("kid") == kid]
    if len(keys) != 1:
        raise SignatureError(f"kid {kid!r} no está (o está repetido) en el JWKS")
    public = _public_key(keys[0])
    r = int.from_bytes(signature[:_COORD], "big")
    s = int.from_bytes(signature[_COORD:], "big")
    try:
        public.verify(
            utils.encode_dss_signature(r, s),
            protected.encode("ascii") + b"." + payload,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise SignatureError("firma no válida") from exc
    return str(kid)


def jwks(signers: Iterable[Signer]) -> dict[str, Any]:
    """JWKS público (`/.well-known/vuln-sentinel/keys.json`). Varias claves permiten la rotación."""
    keys = [s.public_jwk() for s in signers]
    kids = [k["kid"] for k in keys]
    if len(kids) != len(set(kids)):
        raise ValueError(f"kid repetidos en el JWKS: {kids}")
    return {"keys": keys}
