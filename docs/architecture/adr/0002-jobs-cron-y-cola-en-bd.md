---
adr: "0002"
titulo: Container Apps Jobs con cron y cola en la base de datos
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-003, CMP-004, CMP-005, CMP-006, CMP-007]
sustituye: null
---

## Contexto

Ingesta cada 5 min de unas 15 fuentes; volumen bajo; presupuesto de 100 €/mes (D6).

## Decisión

Cuatro Container Apps Jobs con cron. El trabajo pendiente se reparte con
`SELECT … FOR UPDATE SKIP LOCKED` sobre PostgreSQL. Sin Service Bus.

## Alternativas descartadas

- Service Bus: una pieza y un coste más, sin necesidad a este volumen.
- Workers + Queues (KICKOFF): sustituido por D9.

## Consecuencias

Reintentos y estado en un solo sitio, comprobables con tests. Si el volumen crece, se revisa.

## Evidencia

- https://azure.microsoft.com/en-us/pricing/details/container-apps/ (2026-11-25): concesión mensual de 180.000 vCPU·s.
