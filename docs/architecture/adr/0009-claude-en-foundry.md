---
adr: "0009"
titulo: Claude en Microsoft Foundry con identidad gestionada
estado: aceptado (condicionado a G-6)
fecha: 2026-11-25
afecta: [CMP-004, CMP-009]
sustituye: null
---

## Contexto

D5 prefiere Claude en Foundry. Hay que confirmar que se puede desplegar en la suscripción (G-6).

## Decisión

Haiku 5.5 y Sonnet 5.5 en GlobalStandard, Sweden Central, con autenticación por identidad gestionada.

## Alternativas descartadas

- API de Anthropic con clave: es el respaldo si G-6 falla. La clave iría en Key Vault y el tráfico, por un AI Gateway **nuevo** y con autenticación.

## Consecuencias

Sin secretos para la IA. Mismo precio por token que la API directa, facturado en CCU.

**Modelo del agente (P-2):** Sonnet 5.5 en F2. El conjunto de evaluación lo compara con Haiku 5.5
sobre los mismos casos. Si Haiku cumple los umbrales (0 bajadas de nivel, 0 citas inventadas
aceptadas, 100 % en inyección), se cambia a Haiku y se registra aquí.

Decisión de Juan (P-1 y P-2), 2026-11-25.

## Evidencia

- https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/claude-models (2026-11-25)
- https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/claude-models-billing (2026-11-25)
- https://platform.claude.com/docs/en/about-claude/pricing (2026-11-25)
