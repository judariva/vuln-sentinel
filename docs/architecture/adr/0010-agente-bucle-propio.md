---
adr: "0010"
titulo: Agente investigador como bucle propio con tool use
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-004, CMP-009, CMP-014, CTL-003, CTL-004, CTL-006]
sustituye: null
---

## Contexto

D13 pide un único agente y decidir la plataforma con evidencia.

## Decisión

Bucle propio con la API de Claude y tool use, en un Container Apps Job. Trazas OpenTelemetry
(convención GenAI) hacia Application Insights.

## Alternativas descartadas

- Foundry Agent Service: no admite Claude como modelo del agente.

## Consecuencias

Portable entre proveedores de Claude. Los controles de D14 se implementan en nuestro código y se prueban.

## Evidencia

- https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/limits-quotas-regions (act. 18-11-2026; consultado 2026-11-25)
- https://learn.microsoft.com/en-us/azure/foundry/observability/concepts/trace-agent-concept (2026-11-25)
