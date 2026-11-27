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
  type = object({
    runtime = object({
      id           = string
      principal_id = string
      client_id    = string
      name         = string
    })
    publish = object({
      id           = string
      principal_id = string
      client_id    = string
      name         = string
    })
    api = optional(object({
      id           = string
      principal_id = string
      client_id    = string
      name         = string
    }))
  })
  description = <<-EOT
    UAMI del vending (D-3, T16b). `runtime`: cloudflared y los jobs ingest, investigate, daily y
    migrate (es el administrador Entra de PostgreSQL). `publish`: solo el job publish, el único que
    firma el feed (CTL-019, THR-017). `api` (opcional, mínimo privilegio): la API, que está expuesta
    y no escribe; migrate le da un rol de PostgreSQL de SOLO LECTURA. Sin `api`, la API usa runtime.
    `name` es el usuario de PostgreSQL de la identidad (Entra ID).
  EOT
  validation {
    condition = alltrue([for i in concat([var.identities.runtime, var.identities.publish], var.identities.api == null ? [] : [var.identities.api]) :
    can(regex("/providers/Microsoft.ManagedIdentity/userAssignedIdentities/", i.id))])
    error_message = "identities: cada id tiene que ser una identidad asignada por el usuario."
  }
  validation {
    condition     = var.identities.runtime.principal_id != var.identities.publish.principal_id
    error_message = "identities: runtime y publish tienen que ser identidades distintas (solo publish firma el feed)."
  }
  validation {
    condition = var.identities.api == null ? true : (
      var.identities.api.principal_id != var.identities.runtime.principal_id &&
      var.identities.api.principal_id != var.identities.publish.principal_id
    )
    error_message = "identities: api tiene que ser distinta de runtime (admin de PostgreSQL) y de publish (firma)."
  }
}

variable "postgres_entra_admin" {
  type = object({
    principal_id   = string
    principal_name = string
    principal_type = optional(string, "ServicePrincipal")
  })
  description = <<-EOT
    Administrador Entra de PostgreSQL. null = la identidad runtime, que ejecuta el job migrate
    (D-3). Con un grupo o una identidad propia de migraciones, la API deja de ser administradora
    (pregunta abierta de T16b).
  EOT
  default     = null
  validation {
    condition     = var.postgres_entra_admin == null || contains(["ServicePrincipal", "Group", "User"], try(var.postgres_entra_admin.principal_type, ""))
    error_message = "postgres_entra_admin.principal_type: ServicePrincipal | Group | User."
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


variable "key_vault_id" {
  type        = string
  description = "Key Vault privado del landing zone (RBAC). Alcance de los roles sobre secretos y sobre la clave de firma."
  validation {
    condition     = can(regex("/providers/Microsoft.KeyVault/vaults/[A-Za-z0-9-]+$", var.key_vault_id))
    error_message = "key_vault_id: id de un Key Vault."
  }
}

variable "signing_key_id" {
  type        = string
  description = <<-EOT
    Clave de firma del feed (ADR-0008), creada por la plataforma (vending, P-4): EC P-256, solo
    sign y verify, no exportable. Su key_id SIN versión (https://<vault>.vault.azure.net/keys/<nombre>):
    el código resuelve la versión vigente y la usa como `kid`. Tiene que estar en key_vault_id.
  EOT
  validation {
    condition     = can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/keys/[A-Za-z0-9-]+$", var.signing_key_id))
    error_message = "signing_key_id: key_id de Key Vault sin versión (https://<vault>.vault.azure.net/keys/<nombre>)."
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

variable "diagnostic_setting_prefix" {
  type        = string
  description = "Prefijo de los diagnostic settings: diag-<ns>-. Por defecto, el espacio de nombres de la plataforma (diag-gt-); un tercero pone el suyo."
  default     = "diag-gt-"
  validation {
    condition     = can(regex("^diag-[a-z0-9]+-$", var.diagnostic_setting_prefix))
    error_message = "diagnostic_setting_prefix: diag-<ns>- (a-z0-9)."
  }
}

# ------------------------------------------------------------------------------- imagen

variable "image_registry" {
  type        = string
  description = "De dónde sale la imagen: acr (por defecto, D-4: pull con la identidad y AcrPull del vending) o ghcr (solo para terceros: público, por digest, con atestación de images.yml)."
  default     = "acr"
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
    # CIDR privados desde los que la VNet puede llegar a la API (p. ej. el conector del borde de la
    # plataforma, /32). Vacío: solo las apps del entorno. Nunca Internet: el entorno es interno.
    vnet_ingress_from = optional(list(string), [])
  })
  description = "API (CMP-002): ingress interno, escala 0-1 por defecto. Probes obligatorios."
  default     = {}
  validation {
    condition     = var.api.min_replicas >= 0 && var.api.max_replicas >= 1 && var.api.max_replicas >= var.api.min_replicas
    error_message = "api: réplicas coherentes (min >= 0, max >= 1, max >= min)."
  }
  validation {
    # RFC 1918 con su prefijo mínimo (10/8, 172.16/12, 192.168/16). try(): una entrada mal formada
    # se rechaza, no rompe el plan.
    condition = alltrue([
      for c in var.api.vnet_ingress_from : try(
        can(cidrhost(c, 0)) && (
          (startswith(c, "10.") && tonumber(split("/", c)[1]) >= 8) ||
          (can(regex("^172\\.(1[6-9]|2[0-9]|3[01])\\.", c)) && tonumber(split("/", c)[1]) >= 12) ||
          (startswith(c, "192.168.") && tonumber(split("/", c)[1]) >= 16)
        ),
        false
      )
    ])
    error_message = "api.vnet_ingress_from: solo CIDR privados (RFC 1918), nunca 0.0.0.0/0 ni rangos públicos."
  }
  validation {
    condition     = length(var.api.vnet_ingress_from) <= 8
    error_message = "api.vnet_ingress_from: como mucho 8 CIDR (lista cerrada de conectores)."
  }
}

# ------------------------------------------------------------------------------- cloudflared

variable "cloudflared" {
  type = object({
    enabled                = optional(bool, false)
    image                  = optional(string, "")
    tunnel_token_secret_id = optional(string, "")
    metrics_port           = optional(number, 2000)
  })
  description = <<-EOT
    Conector del Tunnel (CMP-010). Opcional: en LAB se usa el conector de la plataforma. Con
    enabled, la imagen va por digest y el token del Tunnel es un secreto de Key Vault (id sin
    versión). Con acr, la imagen tiene que estar replicada en ese ACR (D-4) y se extrae con la
    identidad runtime.
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
    geo_redundant_backup  = optional(bool) # null = activado en prod y desactivado en el resto
    database_name         = optional(string, "vulnsentinel")
  })
  description = "PostgreSQL Flexible (CMP-007, ADR-0003): privado por endpoint privado (D-7), solo Entra ID."
  default     = {}
  validation {
    condition     = var.postgres.backup_retention_days >= 7 && var.postgres.backup_retention_days <= 35
    error_message = "postgres.backup_retention_days: 7-35."
  }
}
