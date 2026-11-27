# Ingress de la API (api.vnet_ingress_from): plan con proveedor simulado, sin nube ni credenciales.
# Valores ficticios, como en examples/golden-lab.

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id = "00000000-0000-0000-0000-000000000000"
    }
  }
}

variables {
  name        = "vulnsentinel"
  environment = "lab"
  location    = "swedencentral"
  resource_group = {
    id   = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-lz-wl-vulnsentinel-lab"
    name = "rg-lz-wl-vulnsentinel-lab"
  }
  tags = {
    Owner              = "owner@example.com"
    Environment        = "lab"
    Criticality        = "LAB"
    DataClassification = "public"
    ManagedBy          = "terraform-workload"
    Workload           = "vulnsentinel"
  }
  identities = {
    runtime = {
      id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-lz-wl-vulnsentinel-lab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-vulnsentinel-runtime-lab"
      principal_id = "11111111-1111-1111-1111-111111111111"
      client_id    = "22222222-2222-2222-2222-222222222222"
      name         = "id-vulnsentinel-runtime-lab"
    }
    publish = {
      id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-lz-wl-vulnsentinel-lab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-vulnsentinel-publish-lab"
      principal_id = "33333333-3333-3333-3333-333333333333"
      client_id    = "44444444-4444-4444-4444-444444444444"
      name         = "id-vulnsentinel-publish-lab"
    }
  }
  container_apps_subnet_id   = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example-network/providers/Microsoft.Network/virtualNetworks/vnet-example/subnets/snet-vulnsentinel-cae"
  key_vault_id               = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-lz-wl-vulnsentinel-lab/providers/Microsoft.KeyVault/vaults/kv-vulnsentinel-lab-0000"
  log_analytics_workspace_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example-monitoring/providers/Microsoft.OperationalInsights/workspaces/law-example"
  signing_key_id             = "https://kv-vulnsentinel-lab-0000.vault.azure.net/keys/feed-signing-es256"
  image_registry             = "acr"
  registry_server            = "acrexample.azurecr.io"
  acr_id                     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example-registry/providers/Microsoft.ContainerRegistry/registries/acrexample"
  image_repository           = "vuln-sentinel"
  image_digest               = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  cloudflared                = { enabled = false }
  investigate_enabled        = false
}

run "default_only_the_environment" {
  command = plan
  assert {
    condition     = azurerm_container_app.api.ingress[0].external_enabled == false
    error_message = "sin vnet_ingress_from, la API solo es visible dentro del entorno"
  }
  assert {
    condition     = length(azurerm_container_app.api.ingress[0].ip_security_restriction) == 0
    error_message = "sin vnet_ingress_from no hay reglas"
  }
}

run "vnet_connector_only" {
  command = plan
  variables {
    api = { vnet_ingress_from = ["10.0.24.4/32"] }
  }
  assert {
    condition     = azurerm_container_app.api.ingress[0].external_enabled == true
    error_message = "con vnet_ingress_from, la API es visible en la VNet"
  }
  assert {
    condition = alltrue([
      for r in azurerm_container_app.api.ingress[0].ip_security_restriction :
      r.action == "Allow" && r.ip_address_range == "10.0.24.4/32"
    ]) && length(azurerm_container_app.api.ingress[0].ip_security_restriction) == 1
    error_message = "una sola regla Allow para el conector"
  }
  assert {
    condition     = azurerm_container_app.api.ingress[0].allow_insecure_connections == false
    error_message = "solo TLS"
  }
}

run "rejects_public_cidr" {
  command = plan
  variables {
    api = { vnet_ingress_from = ["0.0.0.0/0"] }
  }
  expect_failures = [var.api]
}

run "rejects_wide_private_prefix" {
  command = plan
  variables {
    api = { vnet_ingress_from = ["172.0.0.0/8"] }
  }
  expect_failures = [var.api]
}

run "rejects_garbage" {
  command = plan
  variables {
    api = { vnet_ingress_from = ["no-es-un-cidr"] }
  }
  expect_failures = [var.api]
}
