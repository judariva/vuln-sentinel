# Ejemplo: cómo instancia la plataforma el módulo para dev (criticality LAB).
# VALORES FICTICIOS: ningún tenant, suscripción, nombre de recurso, rango ni correo real (regla 8).
# En la plataforma, cada valor sale de las salidas del landing zone (vending) y el módulo se fija
# por versión:
#
#   source = "git::https://github.com/<owner>/vuln-sentinel.git//infra/terraform/modules/vuln-sentinel?ref=<tag>"
#
# Aquí apunta a la ruta local para que la CI lo valide. Sin backend: nunca se aplica desde este repo.

terraform {
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.81.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "2.14.0"
    }
  }
}

provider "azurerm" {
  features {}
  # Autenticación por OIDC desde el pipeline de la plataforma (sin secretos de cliente).
  use_oidc                        = true
  resource_provider_registrations = "none"
}

provider "azapi" {
  use_oidc = true
}

locals {
  sub = "/subscriptions/00000000-0000-0000-0000-000000000000"
  rg  = "rg-lz-wl-vulnsentinel-dev"

  # Salidas del landing zone (ficticias). El vending da hoy una sola UAMI por workload; aquí se usa
  # la misma para todos los componentes (pregunta abierta de T16: una por componente).
  uami = {
    id           = "${local.sub}/resourceGroups/${local.rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-vulnsentinel-dev"
    principal_id = "11111111-1111-1111-1111-111111111111"
    client_id    = "22222222-2222-2222-2222-222222222222"
    name         = "id-vulnsentinel-dev"
  }
}

module "vuln_sentinel" {
  source = "../../modules/vuln-sentinel"

  name        = "vulnsentinel"
  environment = "dev"
  location    = "swedencentral"

  resource_group = {
    id   = "${local.sub}/resourceGroups/${local.rg}"
    name = local.rg
  }

  tags = {
    Owner              = "owner@example.com"
    Environment        = "dev"
    Criticality        = "LAB"
    DataClassification = "public"
    ManagedBy          = "terraform-workload"
    Workload           = "vulnsentinel"
  }

  identities = {
    for c in ["api", "ingest", "investigate", "publish", "daily", "migrate"] : c => local.uami
  }

  container_apps_subnet_id     = "${local.sub}/resourceGroups/rg-example-network/providers/Microsoft.Network/virtualNetworks/vnet-example/subnets/snet-vulnsentinel-cae"
  postgres_subnet_id           = "${local.sub}/resourceGroups/rg-example-network/providers/Microsoft.Network/virtualNetworks/vnet-example/subnets/snet-vulnsentinel-psql"
  postgres_private_dns_zone_id = "${local.sub}/resourceGroups/rg-example-network/providers/Microsoft.Network/privateDnsZones/privatelink.postgres.database.azure.com"
  key_vault_id                 = "${local.sub}/resourceGroups/${local.rg}/providers/Microsoft.KeyVault/vaults/kv-vulnsentinel-dev-0000"
  log_analytics_workspace_id   = "${local.sub}/resourceGroups/rg-example-monitoring/providers/Microsoft.OperationalInsights/workspaces/law-example"

  # Imagen publicada por images.yml en GHCR, por digest (el de ceros no existe).
  image_registry   = "ghcr"
  registry_server  = "ghcr.io"
  image_repository = "example/vuln-sentinel"
  image_digest     = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

  # dev LAB: el Tunnel lo pone el conector de la plataforma; cloudflared del módulo, apagado.
  cloudflared = { enabled = false }

  investigate_enabled = false
}
