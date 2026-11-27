"""Firma del feed: JWS detached ES256 sobre los bytes exactos (RFC 7797, ADR-0008).

Formato: JWS compacto con el payload separado, `<cabecera>..<firma>`. La cabecera protegida es
`{"alg":"ES256","b64":false,"crit":["b64"],"kid":…}` y la entrada firmada es
`ASCII(BASE64URL(cabecera)) || "." || bytes del documento` (RFC 7797, §3). La firma ES256 es
`r || s`, 64 bytes (RFC 7518, §3.4).

La firma va detrás de la interfaz `Signer`:

- `LocalDevSigner`: clave P-256 en memoria, generada en el test o leída de `.cache/`. Nunca en git.
- `KeyVaultSigner`: la clave no exportable de Key Vault (CMP-008), por su API REST y con la
  identidad gestionada del job (F1a). Sin SDK de Azure.
- `UnavailableSigner`: para un proceso que no firma (la API en Azure, D-3).

Cualquiera puede verificar con `openssl` o con una librería JOSE (`examples/verify/`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Protocol

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


class TokenSource(Protocol):
    def token(self, scope: str) -> str: ...


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> tuple[int, bytes]:
        """Petición HTTPS; devuelve (código, cuerpo). Error de red: `OSError`."""
        ...


class UrllibHttpTransport:
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> tuple[int, bytes]:
        if not url.startswith("https://"):
            raise SignatureError("Key Vault solo por HTTPS")
        req = urllib.request.Request(url, data=body, headers=dict(headers), method=method)  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - HTTPS comprobado
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, b""


KV_API_VERSION = "7.4"
KV_SCOPE = "https://vault.azure.net/.default"
_KV_URI_RE = re.compile(
    r"^(https://[a-z0-9-]{3,24}\.vault\.azure\.net)/keys/([A-Za-z0-9-]{1,127})(?:/([0-9a-f]{32}))?/?$"
)


class KeyVaultSigner(Signer):
    """Firma con la clave ES256 no exportable de Azure Key Vault (ADR-0008, CMP-008).

    Sin SDK de Azure: API REST de Key Vault (operaciones `get` y `sign`, api-version 7.4) con un
    token de la identidad gestionada del job. Sin versión en el URI, se fija la versión actual en la
    primera llamada y se usa la misma para firmar y para la clave pública durante todo el proceso.
    Cada firma se comprueba con la clave pública antes de devolverla.
    """

    def __init__(
        self,
        vault_url: str,
        key_name: str,
        key_version: str,
        kid: str,
        tokens: TokenSource | None = None,
        transport: HttpTransport | None = None,
        timeout: float = 10.0,
    ) -> None:
        if not vault_url.startswith("https://"):
            raise ValueError("vault_url tiene que ser HTTPS")
        if not key_name or not kid:
            raise ValueError("key_name y kid son obligatorios")
        self.vault_url = vault_url.rstrip("/")
        self.key_name = key_name
        self.key_version = key_version
        self._kid = kid
        self.tokens = tokens
        self.transport = transport or UrllibHttpTransport()
        self.timeout = timeout
        self._public: ec.EllipticCurvePublicKey | None = None

    @classmethod
    def from_uri(cls, uri: str, kid: str, tokens: TokenSource, **kwargs: Any) -> KeyVaultSigner:
        """`https://<vault>.vault.azure.net/keys/<nombre>[/<versión>]`."""
        m = _KV_URI_RE.fullmatch(uri.strip())
        if not m:
            raise ValueError("VS_SIGNING_KEY_URI no es un URI de clave de Key Vault")
        return cls(m.group(1), m.group(2), m.group(3) or "", kid, tokens, **kwargs)

    @property
    def kid(self) -> str:
        return self._kid

    def _call(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict:
        if self.tokens is None:
            raise SignatureError("KeyVaultSigner sin proveedor de tokens")
        try:
            token = self.tokens.token(KV_SCOPE)
        except Exception as exc:
            # Sin el texto: podría llevar detalles de la identidad.
            raise SignatureError(f"no se pudo obtener el token ({type(exc).__name__})") from None
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        url = f"{self.vault_url}{path}?api-version={KV_API_VERSION}"
        try:
            status, raw = self.transport.request(
                method, url, headers=headers, body=body, timeout=self.timeout
            )
        except OSError as exc:
            raise SignatureError(f"error de red con Key Vault ({type(exc).__name__})") from None
        if status != 200:
            raise SignatureError(f"Key Vault respondió HTTP {status}")
        try:
            return json.loads(raw)
        except ValueError:
            raise SignatureError("respuesta de Key Vault no válida") from None

    def _load(self) -> ec.EllipticCurvePublicKey:
        if self._public is not None:
            return self._public
        path = f"/keys/{self.key_name}" + (f"/{self.key_version}" if self.key_version else "")
        doc = self._call("GET", path)
        try:
            key = doc["key"]
            version = str(key["kid"]).rstrip("/").rsplit("/", 1)[-1]
            if key.get("kty") not in ("EC", "EC-HSM") or key.get("crv") != "P-256":
                raise SignatureError("la clave de Key Vault no es EC P-256")
            x, y = b64url_decode(key["x"]), b64url_decode(key["y"])
        except (KeyError, TypeError, AttributeError):
            raise SignatureError("clave de Key Vault sin los campos esperados") from None
        if len(x) != _COORD or len(y) != _COORD:
            raise SignatureError("coordenadas de la clave de Key Vault no válidas")
        if self.key_version and version != self.key_version:
            raise SignatureError("Key Vault devolvió otra versión de la clave")
        self.key_version = version
        nums = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        )
        self._public = nums.public_key()
        return self._public

    def sign_digest(self, digest: bytes) -> bytes:
        if len(digest) != hashlib.sha256().digest_size:
            raise ValueError("sign_digest espera un resumen SHA-256")
        public = self._load()
        doc = self._call(
            "POST",
            f"/keys/{self.key_name}/{self.key_version}/sign",
            {"alg": ALG, "value": b64url(digest)},
        )
        sig = b64url_decode(str(doc.get("value", "")))
        if len(sig) != 2 * _COORD:
            raise SignatureError(f"firma de Key Vault de {len(sig)} bytes; se esperaban 64")
        der = utils.encode_dss_signature(
            int.from_bytes(sig[:_COORD], "big"), int.from_bytes(sig[_COORD:], "big")
        )
        try:
            public.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        except InvalidSignature:
            raise SignatureError("la firma de Key Vault no casa con su clave pública") from None
        return sig

    def public_jwk(self) -> dict[str, str]:
        return _jwk(self._load(), self._kid)


class SigningUnavailable(RuntimeError):
    """Este proceso no firma (la API en Azure, D-3). La API responde 503 a lo que lo necesite."""


class UnavailableSigner(Signer):
    """Firmante vacío: mantiene el `kid` para todo lo que no firma y falla en cuanto se firma."""

    def __init__(self, kid: str) -> None:
        if not kid:
            raise ValueError("kid vacío")
        self._kid = kid

    @property
    def kid(self) -> str:
        return self._kid

    def sign_digest(self, digest: bytes) -> bytes:
        raise SigningUnavailable("este proceso no tiene clave de firma")

    def public_jwk(self) -> dict[str, str]:
        raise SigningUnavailable("este proceso no tiene clave de firma")


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


def _coord(jwk: Mapping[str, Any], name: str) -> bytes:
    value = jwk.get(name)
    if not isinstance(value, str):
        raise SignatureError(f"coordenada {name} ausente o no es una cadena")
    raw = b64url_decode(value)
    if len(raw) != _COORD:  # RFC 7518 §6.2.1.2: longitud completa, sin quitar ceros
        raise SignatureError(f"coordenada {name} de {len(raw)} bytes; se esperaban 32")
    return raw


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """Huella RFC 7638 (SHA-256, base64url) de una clave EC P-256.

    Es la que se publica fuera del origen (`docs/feed/keys.md` y las notas de cada release) para
    que el consumidor fije la clave: un JWKS sustituido en el origen no la cumple.
    """
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise SignatureError("la clave no es EC P-256")
    x, y = _coord(jwk, "x"), _coord(jwk, "y")
    # Miembros obligatorios en orden lexicográfico y sin espacios (RFC 7638 §3.2 y §3.3).
    canon = f'{{"crv":"P-256","kty":"EC","x":"{b64url(x)}","y":"{b64url(y)}"}}'
    return b64url(hashlib.sha256(canon.encode("ascii")).digest())


def _public_key(jwk: Mapping[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise SignatureError("la clave no es EC P-256")
    if any(k in jwk for k in ("d", "p", "q")):
        raise SignatureError("el JWKS contiene material privado")
    x = int.from_bytes(_coord(jwk, "x"), "big")
    y = int.from_bytes(_coord(jwk, "y"), "big")
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


def verify_detached(
    jws: str,
    payload: bytes,
    jwks: Mapping[str, Any],
    expected_thumbprints: Iterable[str] | None = None,
) -> str:
    """Comprueba la firma sobre los bytes dados. Devuelve el `kid`; si no vale, `SignatureError`.

    Con `expected_thumbprints`, la clave del `kid` tiene que tener una de esas huellas RFC 7638:
    así un JWKS cambiado en el origen no basta para que una firma «verifique».
    """
    protected, header, signature = parse_detached(jws)
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise SignatureError("kid ausente, vacío o que no es una cadena")
    keys = [k for k in jwks.get("keys") or [] if isinstance(k, Mapping) and k.get("kid") == kid]
    if len(keys) != 1:
        raise SignatureError(f"kid {kid!r} no está (o está repetido) en el JWKS")
    if expected_thumbprints is not None:
        pinned = {t.strip() for t in expected_thumbprints if t.strip()}
        if not pinned:
            raise SignatureError("se pidió fijar la clave sin ninguna huella")
        if jwk_thumbprint(keys[0]) not in pinned:
            raise SignatureError(f"la clave del kid {kid!r} no tiene ninguna huella esperada")
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
