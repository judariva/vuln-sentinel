# Verificar el feed

Cada documento del feed (`/v1/vulns/{id}.json`, páginas de cambios, `latest.json`) tiene su firma
en la misma ruta con `.jws`. Es un JWS detached ES256 (RFC 7797, `b64: false`) sobre los **bytes
exactos** del documento (ADR-0008). Guarda el documento tal cual lo recibes: si lo reformateas, la
firma deja de valer.

La clave pública está en `/.well-known/vuln-sentinel/keys.json` (JWKS, con `kid` para la rotación).
`jwks.example.json` muestra el formato: es una clave de ejemplo, no la del servicio, y su parte
privada no existe.

## Con Python

```sh
pip install cryptography
python3 verify.py registro.json registro.json.jws keys.json
```

## Con openssl

```sh
python3 verify.py --pem <kid> keys.json > clave.pem   # o cualquier conversor JWK → PEM
bash verify.sh registro.json registro.json.jws clave.pem
```

`verify.sh` solo usa `openssl` y coreutils: rehace la entrada firmada (`<cabecera>.<documento>`),
pasa la firma `r||s` a DER con `openssl asn1parse` y verifica con `openssl dgst -sha256 -verify`.

`tests/test_feed_sign.py` firma un documento y lo verifica con los dos scripts.
