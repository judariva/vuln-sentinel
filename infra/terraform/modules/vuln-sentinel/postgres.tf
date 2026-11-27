# PostgreSQL Flexible (CMP-007, ADR-0003). CONDICIONAL del patrón de Container Apps: privado y con
# Entra ID.
# - Acceso privado por endpoint privado: sin acceso público, sin subred delegada por workload y sin
#   crear zonas. Por defecto el endpoint lo crea la plataforma (D-7 de golden), con las salidas
#   postgres.id y postgres.name; el módulo solo lo crea si recibe private_endpoint_subnet_id
#   (landing zones sin esa capacidad).
# - Solo Entra ID: sin contraseña de administrador ni autenticación por contraseña. Por defecto el
#   administrador Entra es la identidad runtime (job migrate); los demás componentes entran con su
#   identidad y los roles de base de datos que les da la migración.
# - TLS obligatorio.
# - Sin prevent_destroy (no admite variables y el contrato de retirada exige poder destruir). En
#   prod la protección la dan el contrato de retirada de la plataforma y un bloque lifecycle en la
#   raíz de prod (ADR-0025).

locals {
  postgres_admin = var.postgres_entra_admin != null ? var.postgres_entra_admin : {
    principal_id   = var.identities.runtime.principal_id
    principal_name = var.identities.runtime.name
    principal_type = "ServicePrincipal"
  }
}

# Sin prevent_destroy a propósito (respuesta 7 de Juan, T16b): ver la cabecera.
# tflint-ignore: azurerm_resources_missing_prevent_destroy
resource "azurerm_postgresql_flexible_server" "this" {
  # Supresión acotada a este recurso (T16b):
  # checkov:skip=CKV_AZURE_136:Geo-backup por entorno, no literal. postgres.geo_redundant_backup null = activado en prod y desactivado en lab, dev y pre (respuesta 4 de Juan, T16b); Checkov no evalúa la expresión.
  name                          = local.names.postgres
  location                      = var.location
  resource_group_name           = var.resource_group.name
  version                       = var.postgres.version
  sku_name                      = var.postgres.sku_name
  storage_mb                    = var.postgres.storage_mb
  auto_grow_enabled             = false
  backup_retention_days         = var.postgres.backup_retention_days
  geo_redundant_backup_enabled  = local.postgres_geo_backup
  public_network_access_enabled = false
  tags                          = var.tags

  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = false
    tenant_id                     = data.azurerm_client_config.current.tenant_id
  }

  lifecycle {
    # Azure elige la zona al crear; cambiarla después no es un cambio del módulo.
    ignore_changes = [zone]
  }
}

resource "azurerm_private_endpoint" "postgres" {
  count                         = var.private_endpoint_subnet_id == null ? 0 : 1
  name                          = local.names.postgres_pe
  location                      = var.location
  resource_group_name           = var.resource_group.name
  subnet_id                     = var.private_endpoint_subnet_id
  custom_network_interface_name = "nic-${local.names.postgres_pe}"
  tags                          = var.tags

  private_service_connection {
    name                           = "psc-${local.names.postgres}"
    private_connection_resource_id = azurerm_postgresql_flexible_server.this.id
    subresource_names              = ["postgresqlServer"]
    is_manual_connection           = false
  }

  # Registro A del endpoint en la zona privatelink de la plataforma.
  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [var.postgres_private_dns_zone_id]
  }

  lifecycle {
    precondition {
      condition     = var.postgres_private_dns_zone_id != null
      error_message = "Con private_endpoint_subnet_id hace falta postgres_private_dns_zone_id."
    }
  }
}

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "admin" {
  server_name         = azurerm_postgresql_flexible_server.this.name
  resource_group_name = var.resource_group.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = local.postgres_admin.principal_id
  principal_name      = local.postgres_admin.principal_name
  principal_type      = local.postgres_admin.principal_type
}

# TLS obligatorio (ya es el valor por defecto; se fija para no depender de él).
resource "azurerm_postgresql_flexible_server_configuration" "require_tls" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.this.id
  value     = "on"
}

# Sin prevent_destroy a propósito (respuesta 7 de Juan, T16b): ver la cabecera.
# tflint-ignore: azurerm_resources_missing_prevent_destroy
resource "azurerm_postgresql_flexible_server_database" "this" {
  name      = var.postgres.database_name
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_monitor_diagnostic_setting" "postgres" {
  name                       = local.names.diag_postgres
  target_resource_id         = azurerm_postgresql_flexible_server.this.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category_group = "allLogs"
  }
}
