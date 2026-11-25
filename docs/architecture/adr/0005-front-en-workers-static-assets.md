---
adr: "0005"
titulo: Front en Workers static assets
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-001]
sustituye: null
---

## Contexto

El portal es un consumidor más de la API pública (D10).

## Decisión

Front estático servido con Cloudflare Workers static assets. Lee la API pública como cualquier cliente.

## Alternativas descartadas

- Servir el front desde Container Apps: coste y una réplica más.

## Consecuencias

Coste cero en estáticos. Si se activa la caché de Workers, esas peticiones pasan a cobrarse.

## Evidencia

- https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/ (2026-11-25)
