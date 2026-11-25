---
adr: "0006"
titulo: Python 3.13 para núcleo y API
estado: aceptado
fecha: 2026-11-25
afecta: [CMP-002, CMP-003, CMP-004, CMP-005, CMP-006]
sustituye: null
---

## Contexto

Hay que comparar rangos de versión de muchos ecosistemas y generar OSV.

## Decisión

Python 3.13, `uv`, FastAPI, Alembic. `univers` y `packageurl-python` para versiones y purl.

## Alternativas descartadas

- TypeScript: menos bibliotecas maduras de rangos de versión multi-ecosistema.

## Consecuencias

Un solo lenguaje en el núcleo. El front va aparte, en React (ADR-0005). Decisión de Juan (P-12),
2026-11-25.

## Evidencia

Pendiente de confirmar en F1a las versiones de `univers` y `packageurl-python`.
