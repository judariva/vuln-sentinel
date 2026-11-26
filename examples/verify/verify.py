#!/usr/bin/env python3
"""Verifica un documento del feed de vuln-sentinel (JWS detached ES256, RFC 7797).

Independiente del código del proyecto: solo necesita `cryptography` (pip install cryptography).

Uso:
    python3 verify.py [opciones] DOCUMENTO DOCUMENTO.jws keys.json
    python3 verify.py --pem KID [--expected-thumbprint H ...] keys.json
    python3 verify.py --list-thumbprints keys.json   # kid y huella de cada clave (para publicarlas)

Las huellas que salen de un JWKS descargado del origen no dan confianza: compáralas con las
publicadas en el repo (docs/feed/keys.md) o en las notas de release.

Opciones:
    --expected-thumbprint H  Huella RFC 7638 de una clave en la que confías (se puede repetir).
                             Publicada en el repo (docs/feed/keys.md) y en las notas de release.
                             Si la clave del `kid` no tiene ninguna de ellas, falla.
    --max-age 30m            Falla si `modified` (o, si no está, `generated_at`) del documento es
                             más antiguo que esto (s, m, h o d; sin unidad, segundos).
    --state FICHERO          Guarda el último `modified` visto y falla si el nuevo es anterior.

Sale con 0 si todo vale, 1 si la firma, la clave o la frescura fallan y 2 si el uso no es válido.
`keys.json` es el JWKS de `/.well-known/vuln-sentinel/keys.json`. La firma cubre los bytes exactos
del documento: no lo reformatees antes de verificar.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

# `timezone.utc` y no `datetime.UTC`: el script tiene que funcionar también con Python < 3.11.
UTC = timezone.utc  # noqa: UP017

# Margen para relojes desajustados: un documento con fecha más allá de esto en el futuro se rechaza
# (si no, envenenaría el estado y bloquearía los siguientes).
CLOCK_SKEW = timedelta(minutes=5)
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class VerifyError(ValueError):
    """La firma, la clave o la frescura no son válidas."""


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str):
        raise VerifyError("valor base64url que no es una cadena")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise VerifyError(f"base64url no válido: {exc}") from exc


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _coord(jwk: dict, name: str) -> bytes:
    raw = b64url_decode(jwk.get(name))
    if len(raw) != 32:
        raise VerifyError(f"coordenada {name} de {len(raw)} bytes; se esperaban 32")
    return raw


def thumbprint(jwk: dict) -> str:
    """Huella RFC 7638 (SHA-256, base64url) de una JWK EC P-256."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise VerifyError("la clave no es EC P-256")
    x, y = b64url(_coord(jwk, "x")), b64url(_coord(jwk, "y"))
    canon = f'{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}'
    return b64url(hashlib.sha256(canon.encode("ascii")).digest())


def find_key(jwks: dict, kid: object, expected: list[str] | None = None) -> dict:
    if not isinstance(kid, str) or not kid:
        raise VerifyError("kid ausente, vacío o que no es una cadena")
    keys = [k for k in jwks.get("keys", []) if isinstance(k, dict) and k.get("kid") == kid]
    if len(keys) != 1:
        raise VerifyError(f"kid {kid!r} no está (o está repetido) en el JWKS")
    jwk = keys[0]
    if expected is not None and thumbprint(jwk) not in expected:
        raise VerifyError(f"la clave del kid {kid!r} no tiene ninguna huella esperada")
    return jwk


def public_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise VerifyError("la clave no es EC P-256")
    x = int.from_bytes(_coord(jwk, "x"), "big")
    y = int.from_bytes(_coord(jwk, "y"), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def verify(payload: bytes, jws: str, jwks: dict, expected: list[str] | None = None) -> str:
    parts = jws.strip().split(".")
    if len(parts) != 3 or parts[1]:
        raise VerifyError("no es un JWS compacto con payload separado")
    protected, _, sig_b64 = parts
    header = json.loads(b64url_decode(protected))
    if not isinstance(header, dict):
        raise VerifyError("cabecera protegida no es un objeto")
    if header.get("alg") != "ES256":
        raise VerifyError("alg distinto de ES256")
    if header.get("b64") is not False or header.get("crit") != ["b64"]:
        raise VerifyError("se exige b64=false y crit=['b64'] (RFC 7797)")
    kid = header.get("kid")
    jwk = find_key(jwks, kid, expected)
    sig = b64url_decode(sig_b64)
    if len(sig) != 64:
        raise VerifyError("firma ES256 de longitud incorrecta")
    der = utils.encode_dss_signature(
        int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    )
    # RFC 7797: entrada firmada = BASE64URL(cabecera) || "." || bytes del documento
    public_key(jwk).verify(
        der, protected.encode("ascii") + b"." + payload, ec.ECDSA(hashes.SHA256())
    )
    return kid


# -- frescura y retroceso --------------------------------------------------------------------------


def parse_age(text: str) -> timedelta:
    m = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", text)
    if not m or int(m.group(1)) <= 0:
        raise argparse.ArgumentTypeError(f"duración no válida: {text!r} (p. ej. 30m, 2h, 90s)")
    return timedelta(seconds=int(m.group(1)) * _UNITS[m.group(2) or "s"])


def parse_ts(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise VerifyError("marca de tiempo ausente o que no es una cadena")
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerifyError(f"marca de tiempo no válida: {value!r}") from exc
    if when.tzinfo is None:
        raise VerifyError(f"marca de tiempo sin zona horaria: {value!r}")
    return when


def document_time(payload: bytes) -> datetime:
    """`modified` del documento o, si no lo tiene, `generated_at`. Sin ninguno, falla."""
    try:
        doc = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerifyError("el documento no es JSON") from exc
    if not isinstance(doc, dict):
        raise VerifyError("el documento no es un objeto JSON")
    for name in ("modified", "generated_at"):
        if name in doc:
            return parse_ts(doc[name])
    raise VerifyError("el documento no lleva modified ni generated_at: no se puede comprobar")


def check_fresh(when: datetime, max_age: timedelta | None, now: datetime) -> None:
    if when > now + CLOCK_SKEW:
        raise VerifyError(f"documento con fecha en el futuro ({when.isoformat()})")
    if max_age is not None and now - when > max_age:
        raise VerifyError(f"documento viejo: {when.isoformat()} supera --max-age ({max_age})")


def read_state(path: str) -> datetime | None:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        # Un estado ilegible no se trata como «primera vez»: eso abriría la puerta al retroceso.
        raise VerifyError(f"estado ilegible en {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise VerifyError(f"estado ilegible en {path}")
    return parse_ts(data.get("modified"))


def write_state(path: str, when: datetime) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"modified": when.astimezone(UTC).isoformat().replace("+00:00", "Z")}, fh)
        fh.write("\n")
    os.replace(tmp, path)  # atómico: nunca queda un estado a medias


def check_state(path: str, when: datetime) -> bool:
    """Falla si `when` es anterior al último visto. Devuelve si hay que guardar el nuevo."""
    last = read_state(path)
    if last is not None and when < last:
        raise VerifyError(
            f"retroceso: el documento ({when.isoformat()}) es anterior al último visto "
            f"({last.isoformat()})"
        )
    return last is None or when > last


# -- línea de órdenes ------------------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="verify.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--pem", metavar="KID")
    p.add_argument("--list-thumbprints", action="store_true")
    p.add_argument("--expected-thumbprint", action="append", metavar="H", dest="thumbprints")
    p.add_argument("--max-age", type=parse_age)
    p.add_argument("--state")
    p.add_argument("files", nargs="+")
    return p


def _join_thumbprints(argv: list[str]) -> list[str]:
    """Una huella base64url puede empezar por «-»: argparse la tomaría por una opción."""
    out, i = [], 0
    while i < len(argv):
        if argv[i] == "--expected-thumbprint" and i + 1 < len(argv):
            out.append(f"--expected-thumbprint={argv[i + 1]}")
            i += 2
        else:
            out.append(argv[i])
            i += 1
    return out


def main(argv: list[str]) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(_join_thumbprints(argv))
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    expected = None
    if args.thumbprints is not None:
        expected = [t.strip() for t in args.thumbprints if t.strip()]
        if not expected:
            sys.stderr.write("--expected-thumbprint vacío\n")
            return 2

    if args.list_thumbprints:
        if len(args.files) != 1 or args.pem is not None or expected is not None:
            sys.stderr.write(__doc__ or "")
            return 2
        with open(args.files[0], encoding="utf-8") as fh:
            jwks = json.load(fh)
        try:
            for jwk in jwks.get("keys", []):
                print(f"{jwk.get('kid')}\t{thumbprint(jwk)}")
        except VerifyError as exc:
            print(f"CLAVE NO VÁLIDA: {exc}")
            return 1
        return 0

    if args.pem is not None:
        if len(args.files) != 1 or args.max_age is not None or args.state is not None:
            sys.stderr.write(__doc__ or "")
            return 2
        with open(args.files[0], encoding="utf-8") as fh:
            jwks = json.load(fh)
        try:
            key = public_key(find_key(jwks, args.pem, expected))
        except VerifyError as exc:
            print(f"CLAVE NO VÁLIDA: {exc}")
            return 1
        sys.stdout.write(
            key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("ascii")
        )
        return 0

    if len(args.files) != 3:
        sys.stderr.write(__doc__ or "")
        return 2
    doc_path, jws_path, jwks_path = args.files
    with open(doc_path, "rb") as fh:
        payload = fh.read()
    with open(jws_path, encoding="ascii") as fh:
        jws = fh.read()
    with open(jwks_path, encoding="utf-8") as fh:
        jwks = json.load(fh)
    try:
        kid = verify(payload, jws, jwks, expected)
    except (InvalidSignature, ValueError, KeyError) as exc:
        print(f"FIRMA NO VÁLIDA: {exc or type(exc).__name__}")
        return 1
    # La frescura solo se mira con la firma ya comprobada: la fecha es un dato firmado.
    if args.max_age is not None or args.state is not None:
        try:
            when = document_time(payload)
            check_fresh(when, args.max_age, datetime.now(UTC))
            save = check_state(args.state, when) if args.state is not None else False
        except VerifyError as exc:
            print(f"DOCUMENTO NO FRESCO: {exc}")
            return 1
        if save:
            write_state(args.state, when)
    pinned = " con huella fijada" if expected is not None else ""
    print(f"Firma válida (kid={kid}){pinned}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
