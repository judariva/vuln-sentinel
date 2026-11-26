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
  apagado, migrate), cloudflared opcional, PostgreSQL Flexible privado solo con Entra ID, clave de
  firma creada por ARM en el Key Vault de la plataforma y diagnósticos `allLogs` al workspace de la
  plataforma. Secretos solo como referencias de Key Vault y probes obligatorios (CTL-032).
- **Lo que el módulo no hace:** crear identidades, asignar roles, crear RG, Key Vault, redes ni
  zonas DNS privadas. Publica `required_platform_grants`: cada rol con su identidad y su alcance
  más estrecho (el secreto, la clave, la DCR), para que lo conceda el vending (CTL-019).
- **Este repo no entra en Azure.** `images.yml` se queda (build, SBOM, atestación). `deploy.yml`
  se retira (queda en `infra/bicep-legacy/workflows/` como referencia). La CI solo valida el módulo
  sin credenciales (CTL-031).
- **Bicep:** a `infra/bicep-legacy/`, como referencia de diseño; no se despliega ni se compila.
- **Imagen:** la variable `image_registry = acr | ghcr` deja las dos rutas abiertas. El patrón de
  Container Apps de la plataforma espera ACR con pull por identidad; el producto publica en GHCR
  (público, por digest, con atestación). Lo decide la plataforma.

Versiones fijadas: azurerm 4.81.0 (última 4.x; la plataforma fija `~> 4.0`) y azapi 2.14.0 (solo
para la clave de firma por el plano de control, porque el runner no llega al plano de datos de un
vault privado). Detalle y fuentes en `infra/terraform/modules/vuln-sentinel/versions.tf`.

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
  `tests/test_terraform.py`. Dos supresiones acotadas al servidor de PostgreSQL y con motivo
  (CKV2_AZURE_57, falso positivo con subred delegada; CKV_AZURE_136, geo-backup por nivel y coste).
- PostgreSQL lleva `prevent_destroy`: la retirada de la entrega exige editar el módulo a propósito.
- La verificación de la procedencia de la imagen antes de aplicar (CTL-026) pasa a la plataforma.
- La tabla del latido (G-7) la crea la plataforma: su esquema de referencia queda en
  `infra/bicep-legacy/platform/modules/heartbeat.bicep` y `tests/test_heartbeat.py` lo contrasta.
- Preguntas abiertas para la plataforma (informe de T16): registro (acr o ghcr), una identidad por
  componente o una compartida, PostgreSQL por subred delegada o por endpoint privado, geo-backup en
  prod, versión exacta en un módulo reutilizable, nombres de los diagnostic settings, retirada
  con `prevent_destroy`.

## Evidencia

- Módulo: `infra/terraform/modules/vuln-sentinel/`; ejemplo `infra/terraform/examples/golden-dev/`.
- `terraform fmt`, `terraform validate` (1.15.7), tflint 0.66.0 con el ruleset azurerm 0.33.0 y
  Checkov 3.4.11 en verde el 2026-11-26 (job `terraform` de la CI).
- Versiones de proveedores: https://registry.terraform.io/v1/providers/hashicorp/azurerm/versions
  y https://registry.terraform.io/v1/providers/Azure/azapi, leídas el 2026-11-26.
- Endpoint privado y PostgreSQL con integración en VNet: «The use of private endpoints isn't
  currently supported on servers created with virtual network integration»
  (https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking-private-link,
  leída el 2026-11-26).
