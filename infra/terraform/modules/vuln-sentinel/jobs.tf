# Container Apps Jobs (CMP-003…CMP-006 y migrate). Todos con la misma imagen; cambia el módulo que
# ejecutan (ENTRYPOINT `python -m`). Programados con cron (UTC) o manuales. Un job no tiene ingress,
# así que no lleva probes (ACA las admite solo como comprobación del contenedor, no del job).

resource "azurerm_container_app_job" "this" {
  for_each                     = local.jobs
  name                         = local.names.job[each.key]
  location                     = var.location
  resource_group_name          = var.resource_group.name
  container_app_environment_id = azurerm_container_app_environment.this.id
  workload_profile_name        = "Consumption"
  replica_timeout_in_seconds   = each.value.timeout
  replica_retry_limit          = 0
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [local.identity[each.key].id]
  }

  dynamic "registry" {
    for_each = local.use_acr ? [1] : []
    content {
      server   = var.registry_server
      identity = local.identity[each.key].id
    }
  }

  dynamic "secret" {
    for_each = each.value.secrets
    content {
      name                = secret.key
      identity            = local.identity[each.key].id
      key_vault_secret_id = secret.value
    }
  }

  dynamic "schedule_trigger_config" {
    for_each = each.value.cron == null ? [] : [each.value.cron]
    content {
      cron_expression          = schedule_trigger_config.value
      parallelism              = 1
      replica_completion_count = 1
    }
  }

  dynamic "manual_trigger_config" {
    for_each = each.value.cron == null ? [1] : []
    content {
      parallelism              = 1
      replica_completion_count = 1
    }
  }

  template {
    container {
      name   = each.key
      image  = local.image
      args   = each.value.args
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        # Para DefaultAzureCredential / ManagedIdentityCredential con identidad de usuario.
        name  = "AZURE_CLIENT_ID"
        value = local.identity[each.key].client_id
      }
      env {
        name  = "VS_DATABASE_USER"
        value = local.identity[each.key].name
      }
      dynamic "env" {
        for_each = merge(local.db_env, local.heartbeat_env, local.traces_env, each.value.env)
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
      dynamic "env" {
        for_each = each.value.secret_env
        content {
          name        = env.key
          secret_name = env.value
        }
      }
    }
  }
}
