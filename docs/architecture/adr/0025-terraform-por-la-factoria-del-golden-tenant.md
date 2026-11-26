---
adr: "0025"
titulo: Terraform por la factoría del Golden Tenant
estado: propuesto
fecha: 2026-11-26
afecta: [CMP-025, CMP-026, CMP-027, CMP-028, CMP-030, CMP-038, CMP-039, FLW-032, FLW-044, FLW-045, CTL-019, CTL-020, CTL-021, CTL-026, CTL-031, CTL-032, THR-010, THR-017, THR-018, THR-019]
sustituye: "0014 (en parte: el pipeline de este repo con Contributor y RBAC Administrator con condición)"
---

## Contexto

El núcleo en Azure estaba en Bicep (T9, T9b): `main.bicep` lo desplegaba `deploy.yml` de este repo
con una identidad OIDC con Contributor y RBAC Administrator con condición sobre el RG (ADR-0014).
La plataforma donde corre (el Golden Tenant de Juan) usa solo Terraform y tiene una factoría de
workloads: un vending crea el landing zone (RG, identidad gestionada, Key Vault privado,
presupuesto, guardarraíles y roles) y la entrega de cada workload se despliega con plan y apply
revisados desde la propia plataforma, con sus identidades de CI.

Mantener Bicep y un pipeline propio con permiso para asignar roles duplica el modelo y deja a este
repo con un privilegio que la plataforma ya ejerce mejor.

## Decisión

Modelo híbrido (decisión de Juan del 2026-11-26):

- **Plataforma.** El vending crea el landing zone del producto con sus nombres
  (`rg-lz-wl-<nombre>-<env>`), la identidad, el Key Vault privado, el presupuesto y los
  guardarraíles, y concede los roles. Despliega el producto con el módulo de este repo fijado por
  versión (CMP-039, FLW-044, FLW-045).
- **Producto.** Un módulo Terraform reutilizable en `infra/terraform/modules/vuln-sentinel/`
  (CMP-038): entorno de ACA interno en VNet, API, jobs (ingest, publish, daily, investigate
  apagado, migrate), cloudflared opcional, PostgreSQL Flexible solo con Entra ID y con endpoint
  privado, y diagnósticos `allLogs` al workspace de la plataforma. Secretos solo como referencias
  de Key Vault y probes obligatorios (CTL-032).
- **Lo que el módulo no hace:** crear identidades, asignar roles, crear RG, Key Vault, la clave de
  firma, redes ni zonas DNS privadas. Publica `required_platform_grants`: cada rol con su
  identidad y su alcance más estrecho (el secreto, la clave, la DCR), para que lo conceda el
  vending (CTL-019).
- **Este repo no entra en Azure.** `images.yml` se queda (build, SBOM, atestación). `deploy.yml`
  se retira (queda en `infra/bicep-legacy/workflows/` como referencia). La CI solo valida el módulo
  sin credenciales (CTL-031).
- **Bicep:** a `infra/bicep-legacy/`, como referencia de diseño; no se despliega ni se compila.

### Ajustes de T16b (respuestas de Juan a las preguntas de T16, 2026-11-26)

1. **Registro:** `acr` por defecto (D-4): ACR Basic, pull con la identidad y AcrPull del vending.
   La imagen de cloudflared se replica al mismo ACR y se extrae con la identidad (una precondición
   lo comprueba). `ghcr` queda como opción para terceros.
2. **Dos UAMI** (D-3): `runtime` para la API, cloudflared y los jobs ingest, investigate, daily y
   migrate; `publish` solo para el job publish. `required_platform_grants` da una fila por
   identidad, rol y alcance: Key Vault Crypto User **sobre la clave** solo para `publish`, AcrPull
   para las dos y Key Vault Secrets User para `runtime` sobre cada secreto que usa.
3. **PostgreSQL con endpoint privado** (D-7) en la subred de endpoints compartida, con grupo de
   zona en la `privatelink.postgres.database.azure.com` de la plataforma. Sin subred delegada.
4. **Geo-backup:** `postgres.geo_redundant_backup` sin fijar = activado en prod y desactivado en
   el resto.
5. **Versiones:** el módulo pone `azurerm >= 4.81.0, < 5.0.0`; la versión exacta y el lock los
   pone la raíz que lo instancia (el ejemplo `golden-lab` fija 4.81.0 y versiona su lock).
6. **Diagnostic settings** con la convención de la plataforma: `diag-gt-<recurso>`. El prefijo es
   una variable para que un tercero ponga el suyo.
7. **Sin `prevent_destroy`** en PostgreSQL: no admite variables y el contrato de retirada exige
   poder destruir. La protección de prod la da el contrato de retirada de la plataforma y la raíz
   de prod. Terraform no admite `lifecycle` en un bloque `module`, así que esa raíz no puede
   ponerlo sobre el módulo: el mecanismo concreto queda como pregunta (informe de T16b).
8. **Clave de firma:** la crea la plataforma (vending, P-4). El módulo recibe su `key_id` sin
   versión (`signing_key_id`) y deriva el alcance ARM del rol. Sin azapi.
9. **Requisito para golden:** el workflow de la plataforma verifica la procedencia de la imagen
   (atestación de `images.yml`, `gh attestation verify` sobre el digest) antes de aplicar
   (CTL-026). El módulo no puede hacerlo.

Versión mínima y fuente en `infra/terraform/modules/vuln-sentinel/versions.tf`.

## Alternativas descartadas

- **Seguir con Bicep y `deploy.yml`.** Dos herramientas sobre la misma plataforma y un pipeline
  con RBAC Administrator en el repo del producto (THR-010).
- **Usar directamente el módulo genérico de Container Apps de la plataforma.** Una sola identidad
  para todo el entorno y sin PostgreSQL ni clave de firma: perdería la identidad por componente
  (THR-017), y un tercero sin esa plataforma no podría desplegar el producto (ADR-0022). El módulo
  aplica los mismos controles CORE con recursos propios.
- **Que el módulo asigne roles.** Rompe el reparto: el RBAC es de la plataforma.

## Consecuencias

- Se gana: un solo modelo de IaC, este repo sin privilegios en Azure (CTL-031) y un módulo que
  otra organización puede usar con su propio landing zone.
- La condición ABAC de ADR-0014 deja de aplicarse a este repo; la sustituye el RBAC del vending.
  El hueco de ADR-0014 (credencial federada añadida a una identidad del RG) pasa a depender de qué
  permisos tenga la identidad de apply de la plataforma sobre el RG.
- Checkov 3.4.11 no tiene checks para Container Apps: los controles CORE se comprueban con
  `tests/test_terraform.py`. Una supresión acotada al servidor de PostgreSQL y con motivo
  (CKV_AZURE_136: el geo-backup depende del entorno y Checkov no evalúa la expresión). Con el
  endpoint privado, CKV2_AZURE_57 pasa. tflint: `azurerm_resources_missing_prevent_destroy`
  ignorado en el servidor y la base de datos, por el punto 7.
- Con dos UAMI se recupera la separación que importa (THR-017: solo `publish` firma), pero no la
  identidad por componente de ADR-0014: la API, cloudflared y los jobs comparten `runtime`. Por
  defecto `runtime` es además el administrador Entra de PostgreSQL (para el job migrate); la
  variable `postgres_entra_admin` permite otro principal.
- La identidad de apply de la plataforma necesita unirse a la subred de endpoints compartida y
  escribir el registro A en la zona privada de PostgreSQL.
- La verificación de la procedencia de la imagen antes de aplicar (CTL-026) es un requisito del
  workflow de golden (punto 9).
- La tabla del latido (G-7) la crea la plataforma: su esquema de referencia queda en
  `infra/bicep-legacy/platform/modules/heartbeat.bicep` y `tests/test_heartbeat.py` lo contrasta.

## Evidencia

- Módulo: `infra/terraform/modules/vuln-sentinel/`; ejemplo `infra/terraform/examples/golden-lab/`.
- `terraform fmt`, `terraform validate` (1.15.7), tflint 0.66.0 con el ruleset azurerm 0.33.0 y
  Checkov 3.4.11 en verde el 2026-11-26 (T16 y T16b; job `terraform` de la CI).
- Versiones de proveedores: https://registry.terraform.io/v1/providers/hashicorp/azurerm/versions,
  leída el 2026-11-26.
- Por qué T16 no usó endpoint privado: con integración en VNet Azure no lo admite («The use of
  private endpoints isn't currently supported on servers created with virtual network
  integration»,
  https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking-private-link,
  leída el 2026-11-26). T16b cambia el modo de red a acceso público desactivado más endpoint
  privado; el servidor aún no existe, así que no hay migración.
