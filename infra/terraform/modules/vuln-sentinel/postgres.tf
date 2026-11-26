# PostgreSQL Flexible (CMP-007, ADR-0003). CONDICIONAL del patrón de Container Apps: privado y con
# Entra ID.
# - Acceso privado por subred delegada y zona DNS privada de la plataforma (entradas): sin acceso
#   público y sin crear zonas.
# - Solo Entra ID: sin contraseña de administrador ni autenticación por contraseña. El
#   administrador Entra es la identidad del job migrate; los demás componentes entran con su
#   identidad y los roles de base de datos que les da la migración.
# - TLS obligatorio.

resource "azurerm_postgresql_flexible_server" "this" {
  # Supresiones acotadas a este recurso (T16; revisión: al decidir la pregunta de T16 o al pasar a prod):
  # checkov:skip=CKV2_AZURE_57:Falso positivo. Acceso privado por subred delegada con public_network_access_enabled = false. Azure no admite endpoint privado en ese modo ("The use of private endpoints isn't currently supported on servers created with virtual network integration", learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking-private-link, leída el 2026-11-26).
  # checkov:skip=CKV_AZURE_136:Nivel y coste. geo_redundant_backup es variable (por defecto false, para dev LAB con el backup local de 7 días). Si prod lo activa es una pregunta abierta de T16 (el historial no se reconstruye desde las fuentes).
  name                          = local.names.postgres
  location                      = var.location
  resource_group_name           = var.resource_group.name
  version                       = var.postgres.version
  sku_name                      = var.postgres.sku_name
  storage_mb                    = var.postgres.storage_mb
  auto_grow_enabled             = false
  backup_retention_days         = var.postgres.backup_retention_days
  geo_redundant_backup_enabled  = var.postgres.geo_redundant_backup
  delegated_subnet_id           = var.postgres_subnet_id
  private_dns_zone_id           = var.postgres_private_dns_zone_id
  public_network_access_enabled = false
  tags                          = var.tags

  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = false
    tenant_id                     = data.azurerm_client_config.current.tenant_id
  }

  lifecycle {
    # El historial (observed_at, source_run, alertas enviadas) no se reconstruye desde las fuentes:
    # ni un destroy ni un cambio que fuerce recrear el servidor pasan sin editar el módulo. La
    # retirada (destroy de la entrega) lo exige a propósito: pregunta abierta de T16.
    prevent_destroy = true
    # Azure elige la zona al crear; cambiarla después no es un cambio del módulo.
    ignore_changes = [zone]
  }
}

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "migrate" {
  server_name         = azurerm_postgresql_flexible_server.this.name
  resource_group_name = var.resource_group.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = var.identities["migrate"].principal_id
  principal_name      = var.identities["migrate"].name
  principal_type      = "ServicePrincipal"
}

# TLS obligatorio (ya es el valor por defecto; se fija para no depender de él).
resource "azurerm_postgresql_flexible_server_configuration" "require_tls" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.this.id
  value     = "on"
}

resource "azurerm_postgresql_flexible_server_database" "this" {
  name      = var.postgres.database_name
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = "UTF8"
  collation = "en_US.utf8"

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_monitor_diagnostic_setting" "postgres" {
  name                       = "diag-${local.names.postgres}"
  target_resource_id         = azurerm_postgresql_flexible_server.this.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category_group = "allLogs"
  }
}
