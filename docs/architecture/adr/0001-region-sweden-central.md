---
adr: "0001"
titulo: Región Sweden Central
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-002, CMP-003, CMP-007, CMP-009]
sustituye: null
---

## Contexto

El núcleo corre en Azure (D9) y la IA prefiere Claude en Foundry (D5).

## Decisión

Todo el núcleo en **Sweden Central**.

## Alternativas descartadas

- West Europe: no tiene Claude en el catálogo de Foundry y Container Apps cuesta ~30 % más.

## Consecuencias

Una sola región europea para cómputo, datos e IA. Los despliegues GlobalStandard de Claude pueden
procesar fuera de la UE: se documenta en la vista de seguridad.

## Evidencia

- Catálogo de modelos por región, consultado en solo lectura el 2026-11-25.
- https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-from-partners (2026-11-25)
- https://prices.azure.com/api/retail/prices (2026-11-25)
