# Claves de firma del feed

El feed se firma con ES256 (JWS detached, RFC 7797; ADR-0008). Las claves públicas se sirven en
`/.well-known/vuln-sentinel/keys.json`, **del mismo origen que el feed**. Quien controle el origen
podría cambiar a la vez los documentos, sus firmas y el JWKS, y la firma «verificaría».

Por eso la huella de cada clave se publica también **fuera del origen**:

- en este fichero, que solo cambia por PR revisado en el repositorio;
- en las notas de cada release.

El consumidor fija esas huellas (`--expected-thumbprint`) y no confía en una clave del JWKS que no
tenga ninguna de ellas. Cómo hacerlo: [`examples/verify/README.md`](../../examples/verify/README.md).

## Huella

Huella RFC 7638 (JWK Thumbprint): SHA-256 de los miembros obligatorios de la JWK, en orden
lexicográfico y sin espacios, en base64url sin relleno. Para una clave EC P-256:

```text
BASE64URL(SHA-256('{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}'))
```

`x` e `y` van con su longitud completa (32 bytes). No dependen del `kid`, del `use` ni del `alg`.
Para calcularlas desde un JWKS: `python3 examples/verify/verify.py --list-thumbprints keys.json`.

## Claves del servicio

| `kid` | Huella RFC 7638 | Válida desde | Retirada | Estado |
|---|---|---|---|---|
| — | — | — | — | Aún no hay clave de producción: se añade aquí, por PR, al crearla en Key Vault |

Reglas:

- Una clave nueva entra en esta tabla **antes** de que el servicio firme con ella, para que los
  consumidores la añadan a sus huellas fijadas durante la rotación.
- Una clave retirada se queda en la tabla con su fecha de retirada. Su fila no se borra.
- Las notas de cada release llevan la tabla vigente.

## Clave de ejemplo

`examples/verify/jwks.example.json` tiene una clave de ejemplo que **no es del servicio** y cuya
parte privada no existe. Sirve para comprobar que calculas la huella igual:

| `kid` | Huella RFC 7638 |
|---|---|
| `example-2026-01` | `hOJM_ycvGa6-izFAn7oa4T5VROaIblHeNkamYcg3H4g` |
