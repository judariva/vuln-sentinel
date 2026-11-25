---
adr: "0011"
titulo: Licencia Apache-2.0 y NOTICE de datos
estado: aceptado (ADR-0018, que lo sustituía, fue rechazado el 2026-11-25)
fecha: 2026-11-25
afecta: []
sustituye: null
---

## Contexto

Producto open source (D1), sostenido con donaciones (ADR-0021): el feed es siempre gratis e igual
para todos. Varias fuentes de datos exigen atribución.

## Decisión

Código bajo Apache-2.0. `NOTICE` con la atribución de cada fuente. Se excluyen los datos con licencia NC/ND.

## Alternativas descartadas

- MIT: sin cláusula de patentes ni un sitio previsto para las atribuciones.
- Open core con FSL-1.1-ALv2 en el motor (ADR-0018): rechazado; el modelo de donaciones pide un
  proyecto 100 % abierto.

Contribuciones: **DCO** (`Signed-off-by`) en todo el repo. No hace falta CLA: no se va a
relicenciar.

## Consecuencias

El feed incluye las atribuciones exigidas (VulnCheck visible, GHSA CC-BY 4.0).

## Evidencia

- https://docs.vulncheck.com/community/vulncheck-kev/attribution (2026-11-25)
- https://github.com/github/advisory-database (2026-11-25)
