# Módulo Terraform `vuln-sentinel`

El producto en Azure sobre un landing zone que ya existe (ADR-0025). Lo instancia la factoría de
la plataforma fijado por versión; otra organización lo puede usar con su propio landing zone
(ADR-0022). Ejemplo: `../../examples/golden-lab/`.

```hcl
module "vuln_sentinel" {
  source = "git::https://github.com/<owner>/vuln-sentinel.git//infra/terraform/modules/vuln-sentinel?ref=<tag>"
  # entradas: ver variables.tf y el ejemplo
}
```

Proveedor: azurerm `>= 4.81.0, < 5.0.0` (`versions.tf`, con fuente y fecha). La versión exacta y
el `.terraform.lock.hcl` los pone la raíz que lo instancia, como hace el ejemplo.

## Qué crea

| Recurso | Nombre | Notas |
|---|---|---|
| Entorno de ACA | `cae-<nombre>-<env>` | En la subred de entrada, interno (sin IP pública), solo perfil Consumption, `logs_destination = azure-monitor` |
| API | `ca-<nombre>-api-<env>` | Ingress solo dentro del entorno por defecto, TLS, probes `/healthz`, escala 0–1 por defecto. Con `api.vnet_ingress_from` (CIDR privados, máximo 8), visible en la VNet solo desde esos CIDR (reglas Allow), para un conector de la plataforma fuera del entorno. Nunca desde Internet: el entorno es interno |
| cloudflared (opcional) | `ca-<nombre>-cfd-<env>` | Sin ingress, 1 réplica, token del Tunnel por referencia de Key Vault, probes `/ready` en el puerto de métricas. Con `acr`, imagen replicada en el ACR. Apagado por defecto: en LAB el conector es el de la plataforma |
| Jobs | `caj-<nombre>-{ing,inv,pub,day,mig}-<env>` | ingest, publish y daily con cron (UTC); investigate manual y con `VS_AGENT_ENABLED=0` mientras `investigate_enabled = false`; migrate manual |
| PostgreSQL Flexible | `psql-<nombre>-<env>-<hash4>` | Sin acceso público, solo Entra ID (administrador por defecto: la identidad runtime), TLS obligatorio. Geo-backup activado en prod y desactivado en el resto. Sin `prevent_destroy` (ver abajo) |
| Diagnósticos | `diag-gt-<recurso>` | `allLogs` del entorno y de PostgreSQL al workspace de entrada. Prefijo configurable (`diagnostic_setting_prefix`) para terceros |

## Qué no crea

RG, identidades, Key Vault, la **clave de firma**, redes, zonas DNS privadas, **endpoints
privados** (tampoco el de PostgreSQL: lo crea la plataforma con `postgres.id` y `postgres.name`;
un landing zone sin esa capacidad lo declara en su raíz) ni **asignaciones de rol**. La salida `required_platform_grants` dice qué rol necesita cada identidad (`runtime` o
`publish`) y sobre qué alcance; lo concede el vending antes de aplicar (si no, las referencias de
Key Vault y el pull de ACR fallan al crear la revisión).

| Identidad | Roles (según las entradas) |
|---|---|
| `runtime` (API, cloudflared, ingest, investigate, daily, migrate) | AcrPull sobre el ACR; Key Vault Secrets User sobre cada secreto que usa; Monitoring Metrics Publisher (DCR, App Insights); Cognitive Services User (Foundry) |
| `publish` (job publish) | AcrPull sobre el ACR (el job extrae su imagen con su identidad); **Key Vault Crypto User sobre la clave de firma**; Monitoring Metrics Publisher; Cognitive Services User; Secrets User solo sobre el secreto de R2 si se da |
| `api` (opcional: la API, si el vending la da; si no, la API va con `runtime`) | AcrPull sobre el ACR; Monitoring Metrics Publisher (App Insights). En PostgreSQL, migrate le crea un rol de **solo lectura** (`VS_DATABASE_READONLY_*`): la API está expuesta y no escribe |

Sin Cost Management Reader: ningún componente consulta Cost Management todavía. Se pedirá con el
colector de coste, no antes.

La identidad que aplica necesita además `Microsoft.Network/virtualNetworks/subnets/join/action`
sobre la subred del entorno, que es de la plataforma y suele estar fuera del RG del workload.

## PostgreSQL y la retirada

`prevent_destroy` no admite variables y el contrato de retirada exige poder destruir la entrega,
así que el módulo no lo lleva. Terraform tampoco admite `lifecycle` en un bloque `module`: la
protección de prod la da el contrato de retirada de la plataforma y lo que decida su raíz de prod
(ADR-0025).

## Entradas principales

| Variable | Qué |
|---|---|
| `name`, `environment`, `location` | `<nombre>` a-z0-9 de 2 a 16; `dev`, `pre`, `prod` o `lab` |
| `resource_group` | `{ id, name }` del landing zone |
| `tags` | Etiquetas obligatorias del baseline (Owner, Environment, Criticality, DataClassification, ManagedBy, y Program o Workload) |
| `identities` | `{ runtime, publish }`, cada una `{ id, principal_id, client_id, name }`; distintas |
| `postgres_entra_admin` | Opcional: otro administrador Entra de PostgreSQL (por defecto, runtime) |
| `container_apps_subnet_id` | Subred del entorno, de la plataforma |
| `key_vault_id`, `signing_key_id`, `log_analytics_workspace_id` | Vault, clave de firma (key_id sin versión, en ese vault) y workspace |
| `image_registry` (`acr` por defecto), `registry_server`, `acr_id`, `image_repository`, `image_digest` | Imagen por digest; `ghcr` solo para terceros |
| `crons`, `investigate_enabled` | Programación (UTC) y agente |
| `cloudflared`, `secret_ids` | Opcionales; secretos solo como ids de Key Vault sin versión |
| `heartbeat`, `application_insights_id`, `application_insights_connection_string`, `foundry_account_id` | Opcionales |
| `postgres` | SKU, almacenamiento, retención y `geo_redundant_backup` (null = según el entorno) |

## Validar en local

Sin credenciales ni backend. Nunca `plan` ni `apply` desde este repo.

```bash
terraform fmt -check -recursive infra/terraform
terraform -chdir=infra/terraform/examples/golden-lab init -backend=false
terraform -chdir=infra/terraform/examples/golden-lab validate
tflint --init --config "$PWD/infra/terraform/.tflint.hcl"
tflint --chdir infra/terraform/modules/vuln-sentinel --config "$PWD/infra/terraform/.tflint.hcl"
uv run --no-project --with checkov==3.4.11 checkov -d infra/terraform/modules/vuln-sentinel --framework terraform
uv run pytest tests/test_terraform.py
```

Checkov no tiene checks para Container Apps: los controles CORE están en `tests/test_terraform.py`.
