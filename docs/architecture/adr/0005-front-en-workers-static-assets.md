---
adr: "0005"
titulo: Front en Workers static assets
estado: aceptado
fecha: 2026-11-25
afecta: [CMP-001]
sustituye: null
---

## Contexto

El portal es un consumidor más de la API pública (D10).

## Decisión

Front **React**, como SPA estática construida con **Vite** (P-12). Se sirve con Cloudflare Workers
static assets y lee la API pública como cualquier cliente. Los hosts, el nombre y la marca se leen
de configuración (ADR-0016).

## Alternativas descartadas

- Astro estático: era la primera propuesta; Juan prefiere React (P-12).
- Servir el front desde Container Apps: coste y una réplica más.

## Consecuencias

Coste cero en estáticos. Si se activa la caché de Workers, esas peticiones pasan a cobrarse.

## Evidencia

- https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/ (2026-11-25)
