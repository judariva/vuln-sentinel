# vuln-sentinel · módulo del producto (T16, ADR-0025). Lo instancia la factoría de la plataforma
# fijado por versión, sobre el landing zone que crea su vending. Lo puede usar un tercero con su
# propio landing zone (ADR-0022).
#
# Crea: entorno de ACA en VNet con ingress interno, la API, los jobs (ingest, publish, daily,
# investigate apagado, migrate), cloudflared opcional, PostgreSQL Flexible privado solo con Entra,
# la clave de firma del feed en el Key Vault de la plataforma y los diagnósticos allLogs.
#
# No crea: RG, identidades, Key Vault, subredes, zonas DNS privadas ni asignaciones de rol. Los
# roles que necesita cada identidad salen en `required_platform_grants` y los concede el vending.
#
# Nunca: ingress externo, secretos en línea, contraseña de PostgreSQL, clave compartida del
# workspace (logs_destination = azure-monitor), imagen por etiqueta.

data "azurerm_client_config" "current" {}

locals {
  use_acr = var.image_registry == "acr"
  image   = "${var.registry_server}/${var.image_repository}@${var.image_digest}"

  # Sufijo de 4 hex para los nombres globales (DNS de PostgreSQL). Estable por RG.
  hash4 = substr(sha1(lower(var.resource_group.id)), 0, 4)

  # Código corto por componente: los nombres de ACA tienen 32 caracteres como máximo.
  codes = {
    api         = "api"
    cloudflared = "cfd"
    ingest      = "ing"
    investigate = "inv"
    publish     = "pub"
    daily       = "day"
    migrate     = "mig"
  }
  names = {
    environment = "cae-${var.name}-${var.environment}"
    postgres    = "psql-${var.name}-${var.environment}-${local.hash4}"
    app         = { for k, c in local.codes : k => "ca-${var.name}-${c}-${var.environment}" }
    job         = { for k, c in local.codes : k => "caj-${var.name}-${c}-${var.environment}" }
  }

  signing_key_name = "feed-signing-es256"

  # Variables comunes. La conexión a PostgreSQL es con token de Entra ID (sin contraseña): el usuario
  # de base de datos es el nombre de la identidad de cada componente.
  db_env = {
    VS_DATABASE_HOST = azurerm_postgresql_flexible_server.this.fqdn
    VS_DATABASE_NAME = azurerm_postgresql_flexible_server_database.this.name
    VS_DATABASE_AUTH = "entra"
  }
  heartbeat_env = var.heartbeat == null ? {} : {
    VS_HEARTBEAT_ENDPOINT = var.heartbeat.ingestion_endpoint
    VS_HEARTBEAT_DCR_ID   = var.heartbeat.dcr_immutable_id
    VS_HEARTBEAT_STREAM   = var.heartbeat.stream_name
  }
  traces_env = var.application_insights_id == null ? {} : {
    APPLICATIONINSIGHTS_AUTHENTICATION_STRING = "Authorization=AAD"
  }

  github_secret = var.secret_ids.github_token == "" ? {} : { "github-token" = var.secret_ids.github_token }
  github_env    = var.secret_ids.github_token == "" ? {} : { VS_GITHUB_TOKEN = "github-token" }
  r2_secret     = var.secret_ids.r2_token == "" ? {} : { "r2-token" = var.secret_ids.r2_token }
  r2_env        = var.secret_ids.r2_token == "" ? {} : { VS_R2_TOKEN = "r2-token" }

  # Jobs (CMP-003…CMP-006 y migrate). El reparto de trabajo y la exclusión mutua van en la BD
  # (FOR UPDATE SKIP LOCKED, ADR-0002): si una ejecución se solapa con la anterior, no se pisan.
  jobs = {
    ingest = {
      args       = ["vs.jobs.ingest"]
      cron       = var.crons.ingest
      timeout    = 280
      secrets    = local.github_secret
      secret_env = local.github_env
      env        = {}
    }
    investigate = {
      args       = ["vs.jobs.investigate"]
      cron       = var.investigate_enabled ? var.crons.investigate : null
      timeout    = 580
      secrets    = local.github_secret
      secret_env = local.github_env
      env        = { VS_AGENT_ENABLED = var.investigate_enabled ? "1" : "0" }
    }
    publish = {
      args       = ["vs.jobs.publish"]
      cron       = var.crons.publish
      timeout    = 580
      secrets    = local.r2_secret
      secret_env = local.r2_env
      env        = { VS_SIGNING_KEY_URI = azapi_resource.signing_key.output.properties.keyUri }
    }
    daily = {
      args       = ["vs.jobs.daily"]
      cron       = var.crons.daily
      timeout    = 1200
      secrets    = {}
      secret_env = {}
      env        = {}
    }
    # Migraciones: manual. Su identidad es el administrador Entra de PostgreSQL; ningún otro
    # componente ni el pipeline administran la BD.
    migrate = {
      args       = ["vs.model.migrate", "upgrade", "head"]
      cron       = null
      timeout    = 900
      secrets    = {}
      secret_env = {}
      env        = {}
    }
  }
}

# ------------------------------------------------------------------------------- entorno de ACA

resource "azurerm_container_app_environment" "this" {
  name                           = local.names.environment
  location                       = var.location
  resource_group_name            = var.resource_group.name
  infrastructure_subnet_id       = var.container_apps_subnet_id
  internal_load_balancer_enabled = true # sin IP pública: al origen solo se llega por el Tunnel (ADR-0004)
  zone_redundancy_enabled        = false
  mutual_tls_enabled             = false # una sola app con ingress: no hay tráfico entre apps
  # Diagnóstico por diagnostic setting (abajo), sin clave compartida del workspace.
  logs_destination = "azure-monitor"
  # Con perfiles de carga, Azure crea este RG gestionado. Fijar el nombre evita que cada plan
  # proponga recrear el entorno.
  infrastructure_resource_group_name = "ME_${local.names.environment}_${var.resource_group.name}_${var.location}"
  tags                               = var.tags

  # Solo el perfil Consumption: nada dedicado (ADR-0002).
  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }

  lifecycle {
    precondition {
      condition     = local.use_acr == can(regex("\\.azurecr\\.io$", var.registry_server))
      error_message = "image_registry y registry_server no casan: acr exige <acr>.azurecr.io y ghcr exige ghcr.io."
    }
    precondition {
      condition     = !local.use_acr || var.acr_id != null
      error_message = "image_registry = acr exige acr_id (alcance de AcrPull en required_platform_grants)."
    }
    precondition {
      condition     = !var.cloudflared.enabled || contains(keys(var.identities), "cloudflared")
      error_message = "cloudflared.enabled exige identities.cloudflared."
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "environment" {
  name                       = "diag-${local.names.environment}"
  target_resource_id         = azurerm_container_app_environment.this.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category_group = "allLogs"
  }
}

# ------------------------------------------------------------------------------- clave de firma

# Clave de firma del feed (ADR-0008): EC P-256 (ES256), solo sign y verify, no exportable. Se crea
# por ARM (plano de control): el vault es privado y el runner no llega a su plano de datos. Que ARM
# la cree con el acceso público desactivado está SIN VERIFICAR (primer despliegue).
resource "azapi_resource" "signing_key" {
  type      = "Microsoft.KeyVault/vaults/keys@2024-11-01"
  name      = local.signing_key_name
  parent_id = var.key_vault_id

  body = {
    properties = {
      kty       = "EC"
      curveName = "P-256"
      keyOps    = ["sign", "verify"]
      attributes = {
        enabled    = true
        exportable = false
      }
    }
  }

  # URI sin versión: el código resuelve la versión vigente y la usa como `kid` (rotación, ADR-0008).
  response_export_values = ["properties.keyUri"]
}
