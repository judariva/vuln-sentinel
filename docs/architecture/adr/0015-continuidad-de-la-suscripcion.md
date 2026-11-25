---
adr: "0015"
titulo: Continuidad de la suscripción de Azure
estado: aceptado
fecha: 2026-11-25
afecta: [CMP-002, CMP-003, CMP-007]
sustituye: null
---

## Contexto

vuln-sentinel es un servicio 24/7 sobre la suscripción de plataforma de Juan. Esa suscripción
tiene una fecha a partir de la cual cambia su modelo de facturación.

## Decisión

Al llegar esa fecha, la suscripción pasa a **pago por uso**, a cargo de Juan. El producto no se
migra ni se para.

## Alternativas descartadas

- Migrar a otra suscripción: rompe las identidades OIDC, el RBAC y los recursos privados del RG.

## Consecuencias

- El coste ya está dimensionado como pago por uso (PLAN.md §14, ≤ 100 €/mes).
- La alerta de presupuesto (G-9) se define sobre el coste real del RG y sigue valiendo.
- Requisito de plataforma G-14: un recordatorio antes de la fecha, con margen para revisar costes.
- La fecha y las condiciones no se publican.

## Evidencia

Decisión de Juan (P-13), 2026-11-25.
