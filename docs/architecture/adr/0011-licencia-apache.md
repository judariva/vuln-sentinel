---
adr: "0011"
titulo: Licencia Apache-2.0 y NOTICE de datos
estado: sustituido por 0018
fecha: 2026-11-25
afecta: []
sustituye: null
---

## Contexto

Producto open source (D1). Varias fuentes de datos exigen atribución.

## Decisión

Código bajo Apache-2.0. `NOTICE` con la atribución de cada fuente. Se excluyen los datos con licencia NC/ND.

## Alternativas descartadas

- MIT: sin cláusula de patentes ni un sitio previsto para las atribuciones.

## Consecuencias

El feed incluye las atribuciones exigidas (VulnCheck visible, GHSA CC-BY 4.0).

## Evidencia

- https://docs.vulncheck.com/community/vulncheck-kev/attribution (2026-11-25)
- https://github.com/github/advisory-database (2026-11-25)
