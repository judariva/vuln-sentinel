# Identidades (D-3 + mínimo privilegio): sin identities.api, la API usa runtime (como hasta ahora); con
# ella, la API usa la suya y migrate recibe el rol de SOLO LECTURA. Proveedor simulado, sin nube.

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

run "sin_api_la_api_usa_runtime" {
  command = plan
  assert {
    condition     = azurerm_container_app.api.identity[0].identity_ids == toset([var.identities.runtime.id])
    error_message = "sin identities.api, la API sigue con runtime"
  }
  assert {
    condition     = !contains([for e in azurerm_container_app_job.this["migrate"].template[0].container[0].env : e.name], "VS_DATABASE_READONLY_ROLE")
    error_message = "sin identities.api, migrate no crea rol de solo lectura"
  }
}

run "con_api_minimo_privilegio" {
  command = plan
  variables {
    identities = {
      runtime = var.identities.runtime
      publish = var.identities.publish
      api = {
        id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-lz-wl-vulnsentinel-lab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-vulnsentinel-api-lab"
        principal_id = "55555555-5555-5555-5555-555555555555"
        client_id    = "66666666-6666-6666-6666-666666666666"
        name         = "id-vulnsentinel-api-lab"
      }
    }
  }
  assert {
    condition     = azurerm_container_app.api.identity[0].identity_ids == toset([var.identities.api.id])
    error_message = "con identities.api, la API usa su identidad"
  }
  assert {
    condition = anytrue([
      for e in azurerm_container_app.api.template[0].container[0].env :
      e.name == "VS_DATABASE_USER" && e.value == "id-vulnsentinel-api-lab"
    ])
    error_message = "el usuario de PostgreSQL de la API es su identidad"
  }
  assert {
    condition = anytrue([
      for e in azurerm_container_app_job.this["migrate"].template[0].container[0].env :
      e.name == "VS_DATABASE_READONLY_ROLE" && e.value == "id-vulnsentinel-api-lab"
    ])
    error_message = "migrate crea el rol de solo lectura de la API"
  }
  assert {
    condition     = azurerm_container_app_job.this["ingest"].identity[0].identity_ids == toset([var.identities.runtime.id])
    error_message = "los jobs siguen con runtime"
  }
}

run "api_no_puede_ser_runtime" {
  command = plan
  variables {
    identities = {
      runtime = var.identities.runtime
      publish = var.identities.publish
      api     = var.identities.runtime
    }
  }
  expect_failures = [var.identities]
}
