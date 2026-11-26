# Módulo Terraform `vuln-sentinel`

El producto en Azure sobre un landing zone que ya existe (ADR-0025). Lo instancia la factoría de
la plataforma fijado por versión; otra organización lo puede usar con su propio landing zone
(ADR-0022). Ejemplo: `../../examples/golden-dev/`.

```hcl
module "vuln_sentinel" {
  source = "git::https://github.com/<owner>/vuln-sentinel.git//infra/terraform/modules/vuln-sentinel?ref=<tag>"
  # entradas: ver variables.tf y el ejemplo
}
```

Proveedores fijados: azurerm 4.81.0 y azapi 2.14.0 (`versions.tf`, con fuente y fecha).

## Qué crea

| Recurso | Nombre | Notas |
|---|---|---|
| Entorno de ACA | `cae-<nombre>-<env>` | En la subred de entrada, interno (sin IP pública), solo perfil Consumption, `logs_destination = azure-monitor` |
| API | `ca-<nombre>-api-<env>` | Ingress interno, TLS, probes `/healthz`, escala 0–1 por defecto |
| cloudflared (opcional) | `ca-<nombre>-cfd-<env>` | Sin ingress, 1 réplica, token del Tunnel por referencia de Key Vault, probes `/ready` en el puerto de métricas. Apagado por defecto: en dev LAB el conector es el de la plataforma |
| Jobs | `caj-<nombre>-{ing,inv,pub,day,mig}-<env>` | ingest, publish y daily con cron (UTC); investigate manual y con `VS_AGENT_ENABLED=0` mientras `investigate_enabled = false`; migrate manual |
| PostgreSQL Flexible | `psql-<nombre>-<env>-<hash4>` | Subred delegada y zona DNS de la plataforma, sin acceso público, solo Entra ID (administrador: la identidad de migrate), TLS obligatorio, `prevent_destroy` |
| Clave de firma | `feed-signing-es256` en el Key Vault de entrada | EC P-256, solo sign y verify, no exportable; por ARM (azapi) |
| Diagnósticos | `diag-<recurso>` | `allLogs` del entorno y de PostgreSQL al workspace de entrada |

## Qué no crea

RG, identidades, Key Vault, redes, zonas DNS privadas ni **asignaciones de rol**. La salida
`required_platform_grants` dice qué rol necesita cada identidad y sobre qué alcance; lo concede el
vending antes de aplicar (si no, las referencias de Key Vault y el pull de ACR fallan al crear la
revisión).

## Entradas principales

| Variable | Qué |
|---|---|
| `name`, `environment`, `location` | `<nombre>` a-z0-9 de 2 a 16; `dev`, `pre`, `prod` o `lab` |
| `resource_group` | `{ id, name }` del landing zone |
| `tags` | Etiquetas obligatorias del baseline (Owner, Environment, Criticality, DataClassification, ManagedBy, y Program o Workload) |
| `identities` | Mapa componente → `{ id, principal_id, client_id, name }` |
| `container_apps_subnet_id`, `postgres_subnet_id`, `postgres_private_dns_zone_id` | Red de la plataforma |
| `key_vault_id`, `log_analytics_workspace_id` | Vault y workspace del landing zone |
| `image_registry`, `registry_server`, `acr_id`, `image_repository`, `image_digest` | Imagen por digest; `acr` (pull por identidad) o `ghcr` (público) |
| `crons`, `investigate_enabled` | Programación (UTC) y agente |
| `cloudflared`, `secret_ids` | Opcionales; secretos solo como ids de Key Vault sin versión |
| `heartbeat`, `application_insights_id`, `application_insights_connection_string`, `foundry_account_id` | Opcionales |

## Validar en local

Sin credenciales ni backend. Nunca `plan` ni `apply` desde este repo.

```bash
terraform fmt -check -recursive infra/terraform
terraform -chdir=infra/terraform/examples/golden-dev init -backend=false
terraform -chdir=infra/terraform/examples/golden-dev validate
tflint --init --config "$PWD/infra/terraform/.tflint.hcl"
tflint --chdir infra/terraform/modules/vuln-sentinel --config "$PWD/infra/terraform/.tflint.hcl"
uv run --no-project --with checkov==3.4.11 checkov -d infra/terraform/modules/vuln-sentinel --framework terraform
uv run pytest tests/test_terraform.py
```

Checkov no tiene checks para Container Apps: los controles CORE están en `tests/test_terraform.py`.
