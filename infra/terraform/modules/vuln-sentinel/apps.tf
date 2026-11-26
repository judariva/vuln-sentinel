# Container Apps: la API (CMP-002) y cloudflared (CMP-010, opcional). Nunca con ingress externo: el
# entorno es interno y al origen solo se llega por el Tunnel (ADR-0004, CTL-008). Revisión Single,
# réplicas explícitas, probes de liveness y readiness, secretos solo como referencias de Key Vault.

resource "azurerm_container_app" "api" {
  name                         = local.names.app["api"]
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = var.resource_group.name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [var.identities["api"].id]
  }

  # ACR: pull con la identidad (AcrPull lo concede la plataforma). GHCR: imagen pública por digest,
  # sin credenciales (pregunta abierta de T16).
  dynamic "registry" {
    for_each = local.use_acr ? [1] : []
    content {
      server   = var.registry_server
      identity = var.identities["api"].id
    }
  }

  ingress {
    external_enabled           = false
    target_port                = var.api.port
    transport                  = "http"
    allow_insecure_connections = false
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = var.api.min_replicas
    max_replicas = var.api.max_replicas

    container {
      name   = "api"
      image  = local.image
      args   = ["vs.api.serve"]
      cpu    = var.api.cpu
      memory = var.api.memory

      env {
        name  = "AZURE_CLIENT_ID"
        value = var.identities["api"].client_id
      }
      env {
        name  = "VS_API_PORT"
        value = tostring(var.api.port)
      }
      env {
        name  = "VS_DATABASE_USER"
        value = var.identities["api"].name
      }
      dynamic "env" {
        for_each = merge(local.db_env, local.traces_env)
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = var.application_insights_id == null ? [] : [1]
        content {
          name  = "APPLICATIONINSIGHTS_CONNECTION_STRING"
          value = var.application_insights_connection_string
        }
      }

      liveness_probe {
        transport = "HTTP"
        port      = var.api.port
        path      = var.api.liveness_path
      }
      readiness_probe {
        transport = "HTTP"
        port      = var.api.port
        path      = var.api.readiness_path
      }
    }
  }
}

# cloudflared: una réplica fija, sin ingress, token del Tunnel desde Key Vault. Probes contra su
# servidor de métricas (/ready devuelve 200 con al menos una conexión al borde).
resource "azurerm_container_app" "cloudflared" {
  count                        = var.cloudflared.enabled ? 1 : 0
  name                         = local.names.app["cloudflared"]
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = var.resource_group.name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [var.identities["cloudflared"].id]
  }

  dynamic "registry" {
    for_each = local.use_acr && var.cloudflared.registry_uses_identity ? [1] : []
    content {
      server   = var.registry_server
      identity = var.identities["cloudflared"].id
    }
  }

  secret {
    name                = "tunnel-token"
    identity            = var.identities["cloudflared"].id
    key_vault_secret_id = var.cloudflared.tunnel_token_secret_id
  }

  template {
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "cloudflared"
      image  = var.cloudflared.image
      args   = ["tunnel", "--no-autoupdate", "--metrics", "0.0.0.0:${var.cloudflared.metrics_port}", "run"]
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name        = "TUNNEL_TOKEN"
        secret_name = "tunnel-token"
      }

      liveness_probe {
        transport = "HTTP"
        port      = var.cloudflared.metrics_port
        path      = "/ready"
      }
      readiness_probe {
        transport = "HTTP"
        port      = var.cloudflared.metrics_port
        path      = "/ready"
      }
    }
  }
}
