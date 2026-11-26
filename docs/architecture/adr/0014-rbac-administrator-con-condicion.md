---
adr: "0014"
titulo: Pipeline con Role Based Access Control Administrator con condición
estado: propuesto
fecha: 2026-11-25
actualizado: 2026-11-26
afecta: [CTL-010, THR-010, CTL-019, THR-017]
sustituye: null
---

> **Sustituido en parte por ADR-0025 (2026-11-26).** Este repo ya no despliega: el pipeline de
> `deploy.yml` y su condición quedan como referencia en `infra/bicep-legacy/`. Los roles los
> concede el vending de la plataforma a partir de `required_platform_grants`.

## Contexto

El pipeline tiene que asignar roles a las identidades del RG. Contributor + User Access
Administrator le permitiría darse a sí mismo cualquier rol (revisión R9).

La primera versión (T9) limitaba los roles y el tipo de principal (`ServicePrincipal`). La revisión
de 2026-11-26 vio el hueco: con eso, el pipeline podía dar los 4 roles a **cualquier** service
principal o identidad gestionada del tenant, incluida la suya o una identidad nueva que él mismo
creara en el RG con Contributor.

## Decisión

Contributor + **Role Based Access Control Administrator** sobre el RG, con una condición ABAC 2.0
que, para escribir y para borrar asignaciones:
- solo admite los roles concretos que necesitan las identidades del RG (KV Crypto User, KV Secrets
  User, Cognitive Services User, Monitoring Metrics Publisher);
- solo admite los `principalId` de las identidades de los componentes que reciben esos roles (api,
  cloudflared, ingest, investigate, publish, daily); `migrate` no recibe ningún rol de Azure y
  queda fuera;
- y solo principales de tipo `ServicePrincipal` (redundante con la lista, se deja como defensa en
  profundidad).

Para que los `principalId` se conozcan al escribir la condición, **las identidades las crea la
plataforma** (`infra/platform/platform.bicep`, módulo `infra/modules/identities.bicep`), en el
mismo despliegue que la identidad del pipeline. `main.bicep` ya no las crea: las recibe por
parámetro (`identityNames`) y las referencia como `existing`.

Consecuencia útil: la plataforma también conoce ya los `principalId` de los jobs para el rol en la
DCR del latido (G-7), y desaparece el segundo paso tras el primer despliegue.

## Por qué queda así

- La clave existe para este caso. La documentación de condiciones lista
  `Microsoft.Authorization/roleAssignments:PrincipalId` con origen de petición y de recurso, tipo
  GUID y operadores `GuidEquals`, `GuidNotEquals`, `ForAnyOfAnyValues:GuidEquals` y
  `ForAnyOfAllValues:GuidNotEquals`
  (https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-authorization-actions-attributes,
  leída el 2026-11-26). Su ejemplo «Constrain roles and specific groups» usa exactamente la forma
  de aquí: `@Request[Microsoft.Authorization/roleAssignments:PrincipalId] ForAnyOfAnyValues:GuidEquals {...}`
  para `roleAssignments/write` y `@Resource[...:PrincipalId]` para `roleAssignments/delete`
  (https://learn.microsoft.com/en-us/azure/role-based-access-control/delegate-role-assignments-examples,
  leída el 2026-11-26). Ninguna de las dos páginas menciona el rol Role Based Access Control
  Administrator por su nombre: las condiciones van sobre la asignación del delegado, sea cual sea
  el rol.
- Que la plataforma cree las identidades no rompe D2 (solo Actions escribe en el producto): las
  identidades son requisito de plataforma, como la del pipeline, y se crean una vez.
- Lista cerrada en lugar de «cualquier identidad del RG»: ABAC no tiene un atributo que diga en
  qué RG vive el principal; la lista es la única forma de nombrarlas.

## Alternativas descartadas

- User Access Administrator sin condición: permite escalar.
- Que la plataforma asigne a mano cada rol: rompe D2 (solo Actions escribe).
- Solo roles y tipo de principal (T9): deja asignar a cualquier identidad del tenant.

## Consecuencias

- Brecha conocida y documentada: los permisos heredados de la suscripción (D3).
- Si una identidad se borra y se recrea, cambia su `principalId`: el pipeline no podrá asignarle
  roles (ni borrar las asignaciones huérfanas) hasta que la plataforma vuelva a desplegar
  `platform.bicep`. Falla cerrado.
- Añadir un componente con identidad exige pasar antes por la plataforma.
- **Hueco abierto (pregunta para Juan):** las identidades viven en el RG del producto, donde el
  pipeline tiene Contributor. Contributor puede añadir una credencial federada a una de ellas (por
  ejemplo, `publish`, que firma el feed) y usarla desde fuera de Azure. No le da un rol nuevo, pero
  sí una vía persistente. Alternativa: un RG aparte de la plataforma para las identidades, con
  Managed Identity Operator (solo leer y asignar) para el pipeline.
- Límite de longitud de la condición: SIN VERIFICAR (las páginas citadas no lo dan). Con 4 roles
  y 6 identidades la condición ronda los 1.500 caracteres.

## Evidencia

- `infra/platform/modules/pipeline-identity.bicep` (condición), `tests/test_infra.py` (la
  condición lleva RoleDefinitionId, PrincipalId y PrincipalType en las dos ramas; `main.bicep` no
  crea identidades).
- Pendiente en el primer despliegue: un intento de autoasignar Owner se deniega, y uno de asignar
  KV Secrets User a la identidad del pipeline o a una identidad nueva del RG, también.
