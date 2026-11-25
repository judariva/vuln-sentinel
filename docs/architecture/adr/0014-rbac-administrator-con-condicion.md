---
adr: "0014"
titulo: Pipeline con Role Based Access Control Administrator con condición
estado: propuesto
fecha: 2026-11-25
afecta: [CTL-010, THR-010]
sustituye: null
---

## Contexto

El pipeline tiene que asignar roles a las identidades del RG. Contributor + User Access
Administrator le permitiría darse a sí mismo cualquier rol (revisión R9).

## Decisión

Contributor + **Role Based Access Control Administrator** sobre el RG, con una condición que:
- solo permite asignar o quitar los roles concretos que necesitan las identidades del RG;
- solo a principales de tipo `ServicePrincipal`.

## Alternativas descartadas

- User Access Administrator sin condición: permite escalar.
- Que la plataforma asigne a mano cada rol: rompe D2 (solo Actions escribe).

## Consecuencias

Brecha conocida y documentada: los permisos heredados de la suscripción (D3).

## Evidencia

Pendiente: lista final de roles en G-2. Prueba: un intento de autoasignar Owner se deniega.
