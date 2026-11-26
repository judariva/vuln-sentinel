# Verificar el feed

Cada documento del feed (`/v1/vulns/{id}.json`, páginas de cambios, `latest.json`) tiene su firma
en la misma ruta con `.jws`. Es un JWS detached ES256 (RFC 7797, `b64: false`) sobre los **bytes
exactos** del documento (ADR-0008). Guarda el documento tal cual lo recibes: si lo reformateas, la
firma deja de valer.

La clave pública está en `/.well-known/vuln-sentinel/keys.json` (JWKS, con `kid` para la rotación).
`jwks.example.json` muestra el formato: es una clave de ejemplo, no la del servicio, y su parte
privada no existe.

## Cómo consumir el feed con seguridad

Una firma válida solo dice que el documento lo firmó la clave del JWKS. No dice que esa clave sea
la del servicio ni que el documento sea reciente. Tres comprobaciones cubren lo que falta:

| Riesgo | Qué pasa | Qué lo para |
|---|---|---|
| Clave sustituida | Quien controla el origen cambia documento, firma y JWKS a la vez | `--expected-thumbprint` |
| Congelación | El origen sigue sirviendo un documento viejo, bien firmado | `--max-age` |
| Retroceso | El origen vuelve a servir un índice anterior al que ya viste | `--state` |

### 1. Fija la clave fuera del origen

Toma las huellas RFC 7638 de [`docs/feed/keys.md`](../../docs/feed/keys.md) en el repositorio o de
las notas de release, **no del JWKS que descargas**. Pásalas con `--expected-thumbprint` (se puede
repetir: durante una rotación fija la clave vieja y la nueva). Si la clave del `kid` no tiene
ninguna, la verificación falla aunque la firma cuadre.

### 2. Exige frescura

`--max-age 30m` falla si el documento es más antiguo que eso. Se mira `modified` y, si no está,
`generated_at`. Úsalo con el índice de cambios (`/v1/feed/{feed}/changes`) y con `latest.json`:
`modified` del índice es el final de la última ejecución del publicador, aunque no cambiara nada,
así que un día tranquilo no parece viejo. Unidades: `s`, `m`, `h`, `d` (sin unidad, segundos).

Un documento sin ninguna de las dos marcas (una hora sellada, por ejemplo) no se puede comprobar y
falla: no uses `--max-age` con él. Una fecha más de 5 minutos en el futuro también falla.

### 3. Recuerda lo último que viste

`--state FICHERO` guarda el último `modified` aceptado y falla si el nuevo es anterior. El mismo
`modified` otra vez vale (el índice no ha cambiado). Usa un fichero por cada URL que vigiles
(el índice de `all`, el de `alerts`, `latest.json`). El estado solo se actualiza cuando todo ha pasado, con escritura
atómica. Si el fichero existe y no se puede leer, falla: no se trata como la primera vez.

Las comprobaciones de fecha se hacen **después** de la firma: la fecha que cuenta es la firmada.

### Ejemplo

```sh
pip install cryptography
python3 verify.py \
  --expected-thumbprint <huella de docs/feed/keys.md> \
  --max-age 30m \
  --state estado-all.json \
  changes.json changes.json.jws keys.json
```

Sale con `0` si todo vale, `1` si falla la firma, la clave, la frescura o el estado, y `2` si el uso
no es válido.

## Con Python

```sh
pip install cryptography
python3 verify.py registro.json registro.json.jws keys.json
python3 verify.py --list-thumbprints keys.json   # kid y huella de cada clave del JWKS
```

## Con openssl

```sh
python3 verify.py --pem <kid> --expected-thumbprint <huella> keys.json > clave.pem
bash verify.sh --expected-thumbprint <huella> registro.json registro.json.jws clave.pem
```

`verify.sh` solo usa `openssl` y coreutils: rehace la entrada firmada (`<cabecera>.<documento>`),
pasa la firma `r||s` a DER con `openssl asn1parse` y verifica con `openssl dgst -sha256 -verify`.
Con `--expected-thumbprint` calcula la huella RFC 7638 a partir de la PEM y falla si no coincide.
`verify.sh` no comprueba frescura ni estado: para eso, `verify.py`.

`tests/test_feed_sign.py` y `tests/test_feed_trust.py` firman documentos y los verifican con los dos
scripts, también con un JWKS sustituido y con documentos viejos o anteriores al último visto.
