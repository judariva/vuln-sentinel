# Salidas sin secretos.

locals {
  # Componentes que usan la imagen del producto (AcrPull con acr).
  product_components = concat(["api"], keys(local.jobs))
  acr_pullers = !local.use_acr ? [] : concat(
    local.product_components,
    var.cloudflared.enabled && var.cloudflared.registry_uses_identity ? ["cloudflared"] : [],
  )

  # Quién lee qué secreto. Alcance: el secreto, no el vault (G-2).
  secret_readers = concat(
    var.cloudflared.enabled ? [{ component = "cloudflared", secret = var.cloudflared.tunnel_token_secret_id }] : [],
    var.secret_ids.github_token == "" ? [] : [
      for c in ["ingest", "investigate"] : { component = c, secret = var.secret_ids.github_token }
    ],
    var.secret_ids.r2_token == "" ? [] : [{ component = "publish", secret = var.secret_ids.r2_token }],
  )

  # El vending concede los roles sobre recursos ARM: el id del secreto se da como recurso
  # (<vault>/secrets/<nombre>), no como URI del plano de datos.
  grants_raw = concat(
    [for c in local.acr_pullers : {
      component = c
      role      = "AcrPull"
      scope     = var.acr_id
      reason    = "pull de la imagen con la identidad (sin usuario admin ni pull anónimo)"
    }],
    [for r in local.secret_readers : {
      component = r.component
      role      = "Key Vault Secrets User"
      scope     = "${var.key_vault_id}/secrets/${regex("/secrets/([A-Za-z0-9-]+)$", r.secret)[0]}"
      reason    = "referencia de Key Vault del secreto en la app o el job"
    }],
    [{
      component = "publish"
      role      = "Key Vault Crypto User"
      scope     = azapi_resource.signing_key.id
      reason    = "firma del feed con la clave ES256 no exportable (ADR-0008)"
      }, {
      component = "daily"
      role      = "Cost Management Reader"
      scope     = var.resource_group.id
      reason    = "coste real del RG para la pantalla de transparencia (G-17)"
    }],
    var.heartbeat == null ? [] : [for c in ["ingest", "investigate", "publish", "daily"] : {
      component = c
      role      = "Monitoring Metrics Publisher"
      scope     = var.heartbeat.dcr_id
      reason    = "latido por la Logs Ingestion API (G-7)"
    }],
    var.application_insights_id == null ? [] : [for c in ["api", "ingest", "investigate", "publish", "daily"] : {
      component = c
      role      = "Monitoring Metrics Publisher"
      scope     = var.application_insights_id
      reason    = "trazas OTel con Entra ID, sin clave local"
    }],
    var.foundry_account_id == null ? [] : [for c in ["investigate", "publish"] : {
      component = c
      role      = "Cognitive Services User"
      scope     = var.foundry_account_id
      reason    = "Claude en Foundry: investigador y redacción (ADR-0009)"
    }],
  )
}

output "required_platform_grants" {
  description = <<-EOT
    Roles que el vending debe conceder antes (o en el mismo cambio) para que el producto funcione.
    El módulo no crea ninguna asignación. Una fila por componente; principal_id ya resuelto (si
    varias claves comparten UAMI, hay filas repetidas por principal y alcance: se concede una vez).
    PostgreSQL no aparece: sus roles son de base de datos y los crea el job migrate.
  EOT
  value = [for g in local.grants_raw : merge(g, {
    principal_id = var.identities[g.component].principal_id
  })]
}

output "container_app_environment_id" {
  description = "Id del entorno de ACA."
  value       = azurerm_container_app_environment.this.id
}

output "container_app_environment_default_domain" {
  description = "Dominio interno del entorno: la zona DNS privada para consumidores de otras VNets es de la plataforma."
  value       = azurerm_container_app_environment.this.default_domain
}

output "container_app_environment_static_ip" {
  description = "IP interna del balanceador del entorno (registro A de esa zona)."
  value       = azurerm_container_app_environment.this.static_ip_address
}

output "api_internal_fqdn" {
  description = "Origen del Tunnel (conector de la plataforma o cloudflared del módulo)."
  value       = azurerm_container_app.api.ingress[0].fqdn
}

output "jobs" {
  description = "Id de cada job por componente."
  value       = { for k, j in azurerm_container_app_job.this : k => j.id }
}

output "migrate_job_name" {
  description = "Job manual de migraciones (se lanza tras cada despliegue que cambie el esquema)."
  value       = azurerm_container_app_job.this["migrate"].name
}

output "postgres" {
  description = "Servidor y base de datos (sin credenciales: solo Entra ID)."
  value = {
    id       = azurerm_postgresql_flexible_server.this.id
    fqdn     = azurerm_postgresql_flexible_server.this.fqdn
    database = azurerm_postgresql_flexible_server_database.this.name
  }
}

output "signing_key" {
  description = "Clave de firma: id ARM (alcance del rol) y URI sin versión (VS_SIGNING_KEY_URI)."
  value = {
    id  = azapi_resource.signing_key.id
    uri = azapi_resource.signing_key.output.properties.keyUri
  }
}
