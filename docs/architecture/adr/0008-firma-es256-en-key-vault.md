---
adr: "0008"
titulo: Firma ES256 (JWS detached) con clave no exportable en Key Vault
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-005, CMP-008]
sustituye: null
---

## Contexto

El feed debe ser verificable por cualquiera sin IA y la clave no debe salir nunca del almacén.

## Decisión

JWS detached (RFC 7797, `b64:false`) con ES256 sobre los bytes exactos del documento. La firma la
hace Key Vault (operación `sign`). Clave pública en `/.well-known/vuln-sentinel/keys.json`.

## Alternativas descartadas

- Ed25519 en el proceso: la clave tendría que estar en memoria. Ed25519 en KV Standard: SIN VERIFICAR.
- Sigstore: poco práctico desde un job sin OIDC de usuario.

## Consecuencias

Verificable con `openssl` y con cualquier librería JOSE. Rotación por `kid`.

## Evidencia

Pendiente de comprobar en F1a la operación `sign` de KV con ES256 y su coste por operación.
