# Ejemplo: cómo instancia la plataforma el módulo en lab (criticality LAB).
# VALORES FICTICIOS: ningún tenant, suscripción, nombre de recurso, rango ni correo real (regla 8).
# En la plataforma, cada valor sale de las salidas del landing zone (vending) y el módulo se fija
# por versión:
#
#   source = "git::https://github.com/<owner>/vuln-sentinel.git//infra/terraform/modules/vuln-sentinel?ref=<tag>"
#
# Aquí apunta a la ruta local para que la CI lo valide. Sin backend: nunca se aplica desde este repo.
#
# Esta raíz fija la versión exacta del proveedor y versiona su lock; el módulo solo pone el rango.

terraform {
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.81.0"
    }
  }
}

provider "azurerm" {
  features {}
  # Autenticación por OIDC desde el pipeline de la plataforma (sin secretos de cliente).
  use_oidc                        = true
  resource_provider_registrations = "none"
}

locals {
  sub = "/subscriptions/00000000-0000-0000-0000-000000000000"
  rg  = "rg-lz-wl-vulnsentinel-lab"
  net = "${local.sub}/resourceGroups/rg-example-network/providers/Microsoft.Network"
  kv  = "kv-vulnsentinel-lab-0000"
}

module "vuln_sentinel" {
  source = "../../modules/vuln-sentinel"

  name        = "vulnsentinel"
  environment = "lab"
  location    = "swedencentral"

  resource_group = {
    id   = "${local.sub}/resourceGroups/${local.rg}"
    name = local.rg
  }

  tags = {
    Owner              = "owner@example.com"
    Environment        = "lab"
    Criticality        = "LAB"
    DataClassification = "public"
    ManagedBy          = "terraform-workload"
    Workload           = "vulnsentinel"
  }

  # Las dos UAMI del vending (D-3), ficticias.
  identities = {
    runtime = {
      id           = "${local.sub}/resourceGroups/${local.rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-vulnsentinel-runtime-lab"
      principal_id = "11111111-1111-1111-1111-111111111111"
      client_id    = "22222222-2222-2222-2222-222222222222"
      name         = "id-vulnsentinel-runtime-lab"
    }
    publish = {
      id           = "${local.sub}/resourceGroups/${local.rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-vulnsentinel-publish-lab"
      principal_id = "33333333-3333-3333-3333-333333333333"
      client_id    = "44444444-4444-4444-4444-444444444444"
      name         = "id-vulnsentinel-publish-lab"
    }
  }

  # Subred del entorno, de la plataforma. El endpoint privado de PostgreSQL también lo crea la
  # plataforma (D-7) a partir de la salida `postgres`: sin private_endpoint_subnet_id.
  container_apps_subnet_id   = "${local.net}/virtualNetworks/vnet-example/subnets/snet-vulnsentinel-cae"
  key_vault_id               = "${local.sub}/resourceGroups/${local.rg}/providers/Microsoft.KeyVault/vaults/${local.kv}"
  log_analytics_workspace_id = "${local.sub}/resourceGroups/rg-example-monitoring/providers/Microsoft.OperationalInsights/workspaces/law-example"

  # Clave de firma creada por el vending (P-4): key_id sin versión.
  signing_key_id = "https://${local.kv}.vault.azure.net/keys/feed-signing-es256"

  # ACR con pull por identidad (D-4). El digest de ceros no existe.
  image_registry   = "acr"
  registry_server  = "acrexample.azurecr.io"
  acr_id           = "${local.sub}/resourceGroups/rg-example-registry/providers/Microsoft.ContainerRegistry/registries/acrexample"
  image_repository = "vuln-sentinel"
  image_digest     = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

  # LAB: el Tunnel lo pone el conector de la plataforma; cloudflared del módulo, apagado.
  cloudflared = { enabled = false }

  investigate_enabled = false

  # Geo-backup: sin fijarlo, desactivado en lab y activado en prod (respuesta 4).
}

# Retirada y prod: este ejemplo no protege PostgreSQL contra destroy (lab). En prod, Terraform no
# admite `lifecycle` en un bloque `module`: la protección la decide la raíz de prod (ADR-0025).
