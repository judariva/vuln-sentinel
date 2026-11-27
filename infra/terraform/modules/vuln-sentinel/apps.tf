# Container Apps: la API (CMP-002) y cloudflared (CMP-010, opcional). Nunca desde Internet: el
# entorno es interno y al origen solo se llega por el Tunnel (ADR-0004, CTL-008), con el conector
# dentro del entorno o, con api.vnet_ingress_from, uno de la plataforma en la VNet. Revisión Single,
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
    identity_ids = [local.identity["api"].id]
  }

  # ACR (por defecto, D-4): pull con la identidad y AcrPull del vending. GHCR (solo terceros):
  # imagen pública por digest, sin credenciales.
  dynamic "registry" {
    for_each = local.use_acr ? [1] : []
    content {
      server   = var.registry_server
      identity = local.identity["api"].id
    }
  }

  # Por defecto solo la ven las apps del entorno (cloudflared del módulo). Con vnet_ingress_from, la
  # ve la VNet, nunca Internet: el entorno es interno (internal_load_balancer_enabled), y solo desde
  # esos CIDR privados (reglas Allow: lo demás queda denegado). Es el caso de un conector de la
  # plataforma fuera del entorno.
  ingress {
    external_enabled           = length(var.api.vnet_ingress_from) > 0
    target_port                = var.api.port
    transport                  = "http"
    allow_insecure_connections = false
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
    dynamic "ip_security_restriction" {
      for_each = var.api.vnet_ingress_from
      content {
        name             = "allow-${replace(replace(ip_security_restriction.value, ".", "-"), "/", "-")}"
        action           = "Allow"
        ip_address_range = ip_security_restriction.value
        description      = "Conector del borde (vnet_ingress_from)"
      }
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
        value = local.identity["api"].client_id
      }
      env {
        name  = "VS_API_PORT"
        value = tostring(var.api.port)
      }
      env {
        name  = "VS_DATABASE_USER"
        value = local.identity["api"].name
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
    identity_ids = [local.identity["cloudflared"].id]
  }

  # Con acr, la imagen de cloudflared está replicada en el ACR (D-4; lo comprueba una precondición).
  dynamic "registry" {
    for_each = local.use_acr ? [1] : []
    content {
      server   = var.registry_server
      identity = local.identity["cloudflared"].id
    }
  }

  secret {
    name                = "tunnel-token"
    identity            = local.identity["cloudflared"].id
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
