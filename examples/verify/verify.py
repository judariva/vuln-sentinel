#!/usr/bin/env python3
"""Verifica la firma de un documento del feed de vuln-sentinel (JWS detached ES256, RFC 7797).

Independiente del código del proyecto: solo necesita `cryptography` (pip install cryptography).

Uso:
    python3 verify.py DOCUMENTO DOCUMENTO.jws keys.json   # verifica; sale con 0 si es válida
    python3 verify.py --pem KID keys.json                 # escribe la clave pública en PEM

`keys.json` es el JWKS de `/.well-known/vuln-sentinel/keys.json`. La firma cubre los bytes
exactos del documento: no lo reformatees antes de verificar.
"""

from __future__ import annotations

import base64
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def public_key(jwks: dict, kid: str) -> ec.EllipticCurvePublicKey:
    keys = [k for k in jwks.get("keys", []) if k.get("kid") == kid]
    if len(keys) != 1:
        raise ValueError(f"kid {kid!r} no está (o está repetido) en el JWKS")
    jwk = keys[0]
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("la clave no es EC P-256")
    x = int.from_bytes(b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def verify(payload: bytes, jws: str, jwks: dict) -> str:
    protected, empty, sig_b64 = jws.strip().split(".")
    if empty:
        raise ValueError("no es un JWS con payload separado")
    header = json.loads(b64url_decode(protected))
    if header.get("alg") != "ES256":
        raise ValueError("alg distinto de ES256")
    if header.get("b64") is not False or header.get("crit") != ["b64"]:
        raise ValueError("se exige b64=false y crit=['b64'] (RFC 7797)")
    sig = b64url_decode(sig_b64)
    if len(sig) != 64:
        raise ValueError("firma ES256 de longitud incorrecta")
    der = utils.encode_dss_signature(
        int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    )
    # RFC 7797: entrada firmada = BASE64URL(cabecera) || "." || bytes del documento
    public_key(jwks, header.get("kid")).verify(
        der, protected.encode("ascii") + b"." + payload, ec.ECDSA(hashes.SHA256())
    )
    return header["kid"]


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "--pem":
        with open(argv[2], encoding="utf-8") as fh:
            key = public_key(json.load(fh), argv[1])
        sys.stdout.write(
            key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("ascii")
        )
        return 0
    if len(argv) != 3:
        sys.stderr.write(__doc__ or "")
        return 2
    doc_path, jws_path, jwks_path = argv
    with open(doc_path, "rb") as fh:
        payload = fh.read()
    with open(jws_path, encoding="ascii") as fh:
        jws = fh.read()
    with open(jwks_path, encoding="utf-8") as fh:
        jwks = json.load(fh)
    try:
        kid = verify(payload, jws, jwks)
    except (InvalidSignature, ValueError, KeyError) as exc:
        print(f"FIRMA NO VÁLIDA: {exc or type(exc).__name__}")
        return 1
    print(f"Firma válida (kid={kid})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
