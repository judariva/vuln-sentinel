---
adr: "0026"
titulo: Quién firma lo que sirve la API (la API no tiene la clave)
estado: aceptado
fecha: 2026-11-27
afecta: [CMP-002, CMP-005, CMP-008]
sustituye: null
---

## Contexto

La clave de firma (ADR-0008) solo la usa el job de publicación: es la única identidad con permiso
`sign` sobre la clave. La API usa otra identidad y no puede firmar.

Pero la API firma documentos **al servir cada petición**: `FeedPublisher.signature()` se llama desde
las rutas `.jws`. Algunos de esos documentos no existen hasta que llega la petición:

| Documento | ¿Se puede firmar antes? |
|---|---|
| `/v1/vulns/{id}.json` | Sí: no cambia entre dos ejecuciones de publish |
| `/v1/feed/alerts/latest.json` | Sí, si lo genera publish (hoy depende del reloj de la API) |
| `/v1/digest/{día}.json` | Sí: el día está cerrado y es inmutable |
| `/.well-known/vuln-sentinel/keys.json` | Sí: solo cambia al rotar la clave |
| `/v1/feed/{feed}/changes?since=&limit=` | **No**: hay un documento distinto por cada cursor y límite |

Desde la F1a, en Azure, la API recibe un `UnavailableSigner` y responde **503** a los `.jws` y a
`keys.json`. El JSON se sirve igual. Es seguro, pero el feed no es verificable desde la API.

## Opciones

**(a) Publish firma y la API sirve lo firmado.**
- Publish guarda cada documento firmable junto a su JWS: registros, `latest`, `digest` y `keys.json`.
  La API sirve esos bytes tal cual.
- Para `changes`, las páginas cerradas se sellan y se firman (ADR-0019, páginas selladas). La
  cabeza abierta va sin firma, pero cada entrada lleva el `sha256` del registro, y ese registro
  tiene su propia firma. Así el cliente verifica la cadena sin que la API firme nada.
- Coste: una columna `jws` en `feed_record` y una tabla de documentos firmados. Cambia cómo
  responde la API a `changes.jws`.

**(b) Los documentos firmados salen solo de R2 (F1b).**
- Publish escribe los documentos y sus firmas en R2. La API sirve solo JSON para el portal.
- Coste: dos orígenes. El cliente verifica contra R2 y no contra la API.

**(c) Dar `sign` a la identidad de la API.**
- Es lo más sencillo, pero convierte un servicio expuesto en un **oráculo de firma**. Quien
  comprometa la API puede firmar lo que quiera, y esas firmas se verificarían como del feed. Eso
  anula el motivo de firmar.

## Decisión

**(a)**, y **(b)** cuando exista R2: la clave solo la usa publish. Se descarta **(c)**.

Aceptada el 2026-11-27. Hasta que (a) esté implementada, la API sigue respondiendo 503 a los
`.jws` y a `keys.json` en Azure.

## Implementación de (a)

- **Tabla `feed_signature`** (migración 0003): una fila por ruta con el sha256 de los bytes
  firmados, el JWS y el `kid`. Lleva el cuerpo entero solo en lo que la API no puede reconstruir
  igual: `alerts/latest.json` (depende del reloj de publish) y `keys.json` (la API no tiene la
  clave). Las páginas selladas y los resúmenes caducan con la retención.
- **Publish firma en la misma transacción** en la que guarda el feed y cambia `job_state`, que es
  lo que hace recargar a la API. La API nunca ve un registro nuevo sin su firma. Firma lo que no
  tiene firma de esos mismos bytes: registros cambiados, hasta 500 registros antiguos por
  ejecución (relleno), páginas selladas, resúmenes de días cerrados y `latest.json`.
- **La API sirve una firma solo si casa con los bytes que sirve.** Si no hay firma de esos bytes,
  firma en el momento donde hay clave (local) o responde 503 (Azure).
- **La cabeza del índice no se firma en Azure.** Cambia con cada petición. Lo verificable son las
  páginas selladas (`/v1/feed/{feed}/changes/{AAAA-MM-DDTHH}.json`, ahora también en la API) y el
  sha256 de cada registro.
- **El rol de publish** escribe además en `feed_signature`; el de solo lectura la lee.

## Evidencia

- En Azure, publish termina `Succeeded` con `KeyVaultSigner`, y cada firma se comprueba con la
  clave pública antes de devolverla (`vs.feed.sign`). La operación `sign` de Key Vault con ES256
  funciona (pendiente en ADR-0008).
- La API en Azure con `UnavailableSigner`: 200 en el JSON y 503 en los `.jws`
  (`tests/test_azure_runtime.py`).
- Con (a): la API sin clave sirve las firmas de publish y verifican con su JWKS, una firma de otros
  bytes nunca se sirve y la cabeza da 503 (`tests/test_presigned.py`). De punta a punta sobre
  PostgreSQL, incluido el relleno de registros sin firma (`tests/test_jobs.py`).
