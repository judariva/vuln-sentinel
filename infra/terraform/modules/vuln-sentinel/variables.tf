# Entradas del módulo (T16, ADR-0025). Todo lo que crea la plataforma llega por aquí: el módulo no
# crea RG, identidades, Key Vault, zonas DNS privadas ni asignaciones de rol.

# ------------------------------------------------------------------------------- identidad y sitio

variable "name" {
  type        = string
  description = "Nombre corto del workload (a-z0-9, 2-16). Entra en todos los nombres: <tipo>-<nombre>-<env>."
  validation {
    condition     = can(regex("^[a-z0-9]{2,16}$", var.name))
    error_message = "name: 2-16 caracteres a-z0-9."
  }
}

variable "environment" {
  type        = string
  description = "Entorno: dev | pre | prod | lab."
  validation {
    condition     = contains(["dev", "pre", "prod", "lab"], var.environment)
    error_message = "environment: dev | pre | prod | lab."
  }
}

variable "location" {
  type        = string
  description = "Región (ADR-0001: Sweden Central)."
  default     = "swedencentral"
}

variable "resource_group" {
  type = object({
    id   = string
    name = string
  })
  description = "RG del landing zone (salida resource_group del vending)."
}

variable "tags" {
  type        = map(string)
  description = "Etiquetas obligatorias del baseline (salida tags del vending). Se aplican a todo lo que crea el módulo."
  validation {
    condition     = alltrue([for k in ["Owner", "Environment", "Criticality", "DataClassification", "ManagedBy"] : contains(keys(var.tags), k)])
    error_message = "tags: faltan etiquetas obligatorias (Owner, Environment, Criticality, DataClassification, ManagedBy)."
  }
  validation {
    condition     = contains(keys(var.tags), "Program") || contains(keys(var.tags), "Workload")
    error_message = "tags: hace falta Program o Workload."
  }
}

variable "identities" {
  type = map(object({
    id           = string
    principal_id = string
    client_id    = string
    name         = string
  }))
  description = <<-EOT
    UAMI por componente (salida identity del vending). Claves: api, ingest, investigate, publish,
    daily, migrate y, con cloudflared, cloudflared. Varias claves pueden apuntar a la misma UAMI si
    la plataforma solo da una, pero se pierde el mínimo privilegio por componente (ADR-0014).
    `name` es el usuario de PostgreSQL de la identidad (Entra ID).
  EOT
  validation {
    condition     = alltrue([for k in ["api", "ingest", "investigate", "publish", "daily", "migrate"] : contains(keys(var.identities), k)])
    error_message = "identities: faltan componentes (api, ingest, investigate, publish, daily, migrate)."
  }
  validation {
    condition     = alltrue([for i in values(var.identities) : can(regex("/providers/Microsoft.ManagedIdentity/userAssignedIdentities/", i.id))])
    error_message = "identities: cada id tiene que ser una identidad asignada por el usuario."
  }
}

# ------------------------------------------------------------------------------- red y plataforma

variable "container_apps_subnet_id" {
  type        = string
  description = "Subred del entorno de ACA, delegada a Microsoft.App/environments y con NSG (la crea la plataforma). Con perfiles de carga basta /27."
  validation {
    condition     = can(regex("^/subscriptions/.+/subnets/.+$", var.container_apps_subnet_id))
    error_message = "container_apps_subnet_id: id de subred."
  }
}

variable "postgres_subnet_id" {
  type        = string
  description = "Subred delegada a Microsoft.DBforPostgreSQL/flexibleServers (la crea la plataforma)."
  validation {
    condition     = can(regex("^/subscriptions/.+/subnets/.+$", var.postgres_subnet_id))
    error_message = "postgres_subnet_id: id de subred."
  }
}

variable "postgres_private_dns_zone_id" {
  type        = string
  description = "Zona DNS privada de PostgreSQL (privatelink.postgres.database.azure.com o <x>.postgres.database.azure.com) de la plataforma, enlazada a la VNet. El módulo no crea zonas."
  validation {
    condition     = can(regex("/providers/Microsoft.Network/privateDnsZones/.+postgres\\.database\\.azure\\.com$", var.postgres_private_dns_zone_id))
    error_message = "postgres_private_dns_zone_id: id de una zona privada *.postgres.database.azure.com."
  }
}

variable "key_vault_id" {
  type        = string
  description = "Key Vault privado del landing zone (RBAC). El módulo crea en él la clave de firma por el plano de control."
  validation {
    condition     = can(regex("/providers/Microsoft.KeyVault/vaults/[A-Za-z0-9-]+$", var.key_vault_id))
    error_message = "key_vault_id: id de un Key Vault."
  }
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Workspace de diagnóstico de la plataforma (allLogs del entorno de ACA y de PostgreSQL)."
  validation {
    condition     = can(regex("/providers/Microsoft.OperationalInsights/workspaces/", var.log_analytics_workspace_id))
    error_message = "log_analytics_workspace_id: id de un workspace de Log Analytics."
  }
}

# ------------------------------------------------------------------------------- imagen

variable "image_registry" {
  type        = string
  description = "De dónde sale la imagen: acr (pull con la identidad; AcrPull lo concede la plataforma) o ghcr (público, por digest, con atestación de images.yml). Pendiente de la plataforma (pregunta abierta de T16)."
  validation {
    condition     = contains(["acr", "ghcr"], var.image_registry)
    error_message = "image_registry: acr | ghcr."
  }
}

variable "registry_server" {
  type        = string
  description = "Servidor del registro: <acr>.azurecr.io con acr; ghcr.io con ghcr."
  validation {
    condition     = can(regex("^([a-z0-9]+\\.azurecr\\.io|ghcr\\.io)$", var.registry_server))
    error_message = "registry_server: <acr>.azurecr.io o ghcr.io."
  }
}

variable "acr_id" {
  type        = string
  description = "Id del ACR (solo con acr): alcance de AcrPull en required_platform_grants."
  default     = null
}

variable "image_repository" {
  type        = string
  description = "Repositorio de la imagen dentro del registro (p. ej. <owner>/vuln-sentinel)."
  validation {
    condition     = can(regex("^[a-z0-9]+([._/-][a-z0-9]+)*$", var.image_repository))
    error_message = "image_repository: ruta de repositorio en minúsculas."
  }
}

variable "image_digest" {
  type        = string
  description = "Digest de la imagen del producto (sha256:...). Nunca una etiqueta."
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest: sha256:<64 hex>."
  }
}

# ------------------------------------------------------------------------------- jobs

variable "crons" {
  type = object({
    ingest      = optional(string, "*/5 * * * *")
    investigate = optional(string, "*/10 * * * *")
    publish     = optional(string, "*/10 * * * *")
    # 05:00 UTC = 07:00 Europe/Madrid en verano y 06:00 en invierno: nunca después de las 07:00 (§12).
    daily = optional(string, "0 5 * * *")
  })
  description = "Cron de cada job, en UTC (ACA no admite zona horaria)."
  default     = {}
  validation {
    condition     = alltrue([for c in values(var.crons) : length(split(" ", c)) == 5])
    error_message = "crons: expresiones de 5 campos."
  }
}

variable "investigate_enabled" {
  type        = bool
  description = "Agente investigador (ADR-0009). Apagado: el job existe, solo manual y con VS_AGENT_ENABLED=0."
  default     = false
}

# ------------------------------------------------------------------------------- API

variable "api" {
  type = object({
    port           = optional(number, 8080)
    cpu            = optional(number, 0.25)
    memory         = optional(string, "0.5Gi")
    min_replicas   = optional(number, 0)
    max_replicas   = optional(number, 1)
    liveness_path  = optional(string, "/healthz")
    readiness_path = optional(string, "/healthz")
  })
  description = "API (CMP-002): ingress interno, escala 0-1 por defecto. Probes obligatorios."
  default     = {}
  validation {
    condition     = var.api.min_replicas >= 0 && var.api.max_replicas >= 1 && var.api.max_replicas >= var.api.min_replicas
    error_message = "api: réplicas coherentes (min >= 0, max >= 1, max >= min)."
  }
}

# ------------------------------------------------------------------------------- cloudflared

variable "cloudflared" {
  type = object({
    enabled                = optional(bool, false)
    image                  = optional(string, "")
    tunnel_token_secret_id = optional(string, "")
    metrics_port           = optional(number, 2000)
    registry_uses_identity = optional(bool, false)
  })
  description = <<-EOT
    Conector del Tunnel (CMP-010). Opcional: en dev LAB se usa el conector de la plataforma. Con
    enabled, la imagen va por digest y el token del Tunnel es un secreto de Key Vault (id sin
    versión). registry_uses_identity = true si la imagen está en el ACR de registry_server.
  EOT
  default     = {}
  validation {
    condition     = !var.cloudflared.enabled || can(regex("@sha256:[0-9a-f]{64}$", var.cloudflared.image))
    error_message = "cloudflared.image: fijada por digest."
  }
  validation {
    condition     = !var.cloudflared.enabled || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+$", var.cloudflared.tunnel_token_secret_id))
    error_message = "cloudflared.tunnel_token_secret_id: id de secreto de Key Vault sin versión."
  }
}

# ------------------------------------------------------------------------------- secretos opcionales

variable "secret_ids" {
  type = object({
    github_token = optional(string, "")
    r2_token     = optional(string, "")
  })
  description = "Ids sin versión de secretos de Key Vault (los valores los pone la plataforma, con caducidad). Vacío = sin ese secreto."
  default     = {}
  validation {
    condition     = alltrue([for v in values(var.secret_ids) : v == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+$", v))])
    error_message = "secret_ids: solo ids de secreto de Key Vault (sin versión). Secretos en línea prohibidos."
  }
}

# ------------------------------------------------------------------------------- observabilidad e IA

variable "heartbeat" {
  type = object({
    ingestion_endpoint = string
    dcr_id             = string
    dcr_immutable_id   = string
    stream_name        = optional(string, "Custom-VsHeartbeat_CL")
  })
  description = "Latido (G-7): DCR de la plataforma. null = sin latido."
  default     = null
}

variable "application_insights_id" {
  type        = string
  description = "App Insights para trazas OTel con Entra ID (sin clave local). null = sin trazas."
  default     = null
}

variable "application_insights_connection_string" {
  type        = string
  description = "Cadena de conexión de ese App Insights. Con autenticación local desactivada no autoriza nada, pero se trata como sensible."
  default     = null
  sensitive   = true
}

variable "foundry_account_id" {
  type        = string
  description = "Cuenta de Foundry (ADR-0009, G-6). null = aún no existe."
  default     = null
}

# ------------------------------------------------------------------------------- PostgreSQL

variable "postgres" {
  type = object({
    version               = optional(string, "17")
    sku_name              = optional(string, "B_Standard_B1ms")
    storage_mb            = optional(number, 32768)
    backup_retention_days = optional(number, 7)
    geo_redundant_backup  = optional(bool, false)
    database_name         = optional(string, "vulnsentinel")
  })
  description = "PostgreSQL Flexible (CMP-007, ADR-0003): privado por subred delegada, solo Entra ID."
  default     = {}
  validation {
    condition     = var.postgres.backup_retention_days >= 7 && var.postgres.backup_retention_days <= 35
    error_message = "postgres.backup_retention_days: 7-35."
  }
}
