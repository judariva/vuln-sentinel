// Key Vault Secrets User con alcance sobre UN secreto (no sobre el vault). El secreto debe
// existir antes del despliegue: lo crea la plataforma o Juan, con caducidad (G-5).

param vaultName string
param secretName string
param principalIds array
param roleDefinitionGuid string

resource vault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: vaultName
}

resource secret 'Microsoft.KeyVault/vaults/secrets@2024-11-01' existing = {
  parent: vault
  name: secretName
}

resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for p in principalIds: {
    name: guid(secret.id, p, roleDefinitionGuid)
    scope: secret
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitionGuid)
      principalId: p
      principalType: 'ServicePrincipal'
    }
  }
]
