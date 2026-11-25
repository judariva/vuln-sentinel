---
adr: "0007"
titulo: Feed OSV 1.9 extendido
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-002, CMP-005]
sustituye: null
---

## Contexto

El cliente tiene que cruzar el feed con su inventario sin IA (KICKOFF; decisiones en `docs/journey/00-origen-y-decisiones.md`).

## Decisión

Una alerta es un registro OSV 1.9.x. Las extensiones van en `database_specific.vuln_sentinel`.
CSAF VEX queda como exportación posterior.

## Alternativas descartadas

- CSAF 2.1 como base: aún es Committee Specification (CS01, 09-11-2026); más pesado de generar y de consumir.

## Consecuencias

Cruce directo por purl y rangos con herramientas existentes. El CPE va en `database_specific`.

## Evidencia

- https://ossf.github.io/osv-schema/ (v1.9.2, 13-10-2026; consultado 2026-11-25)
- https://docs.oasis-open.org/csaf/csaf/v2.1/csaf-v2.1.html (2026-11-25)
