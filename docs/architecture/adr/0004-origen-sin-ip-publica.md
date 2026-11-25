---
adr: "0004"
titulo: Origen sin IP pública con Cloudflare Tunnel
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-002, CMP-010, CMP-011, CTL-008, THR-008]
sustituye: null
---

## Contexto

El WAF y Access (D4) solo protegen si no se puede llegar al origen por otro camino.

## Decisión

`cloudflared` corre como app interna del entorno de Container Apps. La API tiene ingress interno.

## Alternativas descartadas

- Ingress público con restricción a las IP de Cloudflare y una cabecera secreta: más superficie y un secreto que rotar.

## Consecuencias

Una réplica mínima fija para `cloudflared` (~2-3 €/mes). Prueba: un `curl` directo al origen falla.

## Evidencia

Pendiente de la decisión P-4.
