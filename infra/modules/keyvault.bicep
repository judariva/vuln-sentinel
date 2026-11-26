// Key Vault del producto (CMP-008, ADR-0008):
// - autorización solo por RBAC, sin acceso público, con endpoint privado;
// - clave de firma EC P-256 (ES256) creada dentro del vault, solo «sign» y «verify», no
//   exportable (sin release policy, la clave nunca sale de KV);
// - roles con el alcance más estrecho posible: Crypto User sobre LA clave, Secrets User sobre
//   CADA secreto, nunca sobre el vault entero (G-2).
// Los valores de los secretos (token del Tunnel, token de R2, etc.) no los crea esta plantilla:
// los pone la plataforma o Juan, con caducidad (G-5). La plantilla solo da acceso de lectura.

param location string
param namePrefix string

@description('Sufijo único para el nombre del vault (los nombres de KV son globales).')
param uniqueSuffix string

param privateEndpointSubnetId string
param keyVaultDnsZoneId string

@description('Nombre de la clave de firma del feed.')
param signingKeyName string = 'feed-signing-es256'

@description('principalId que puede firmar con la clave (job publish).')
param signerPrincipalIds array

@description('Lectores por secreto: [{ secret: nombre, principalIds: [...] }]. El secreto debe existir.')
param secretReaders array = []

@description('Protección contra purga. Una vez activada no se puede desactivar.')
param enablePurgeProtection bool = true

param tags object = {}

var roleCryptoUser = '12338af0-0e69-4776-bea7-57ae8d297424' // Key Vault Crypto User
var roleSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User

resource vault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: take('${namePrefix}-kv-${uniqueSuffix}', 24)
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: enablePurgeProtection ? true : null
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
    }
  }
}

// La clave se crea por ARM (plano de control): no necesita acceso de red al vault ni rol de
// datos para el pipeline. SIN VERIFICAR en esta suscripción con el acceso público desactivado
// (se comprueba en el primer despliegue, F1a).
resource signingKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' = {
  parent: vault
  name: signingKeyName
  properties: {
    kty: 'EC'
    curveName: 'P-256'
    keyOps: [
      'sign'
      'verify'
    ]
    attributes: {
      enabled: true
      exportable: false
    }
  }
}

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${vault.name}-pe'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'vault'
        properties: {
          privateLinkServiceId: vault.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
}

resource dnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: privateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'vault'
        properties: {
          privateDnsZoneId: keyVaultDnsZoneId
        }
      }
    ]
  }
}

resource signerRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for p in signerPrincipalIds: {
    name: guid(signingKey.id, p, roleCryptoUser)
    scope: signingKey
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleCryptoUser)
      principalId: p
      principalType: 'ServicePrincipal'
    }
  }
]

module secretRoles 'keyvault-secret-reader.bicep' = [
  for r in secretReaders: {
    name: 'kv-secret-${uniqueString(r.secret)}'
    params: {
      vaultName: vault.name
      secretName: r.secret
      principalIds: r.principalIds
      roleDefinitionGuid: roleSecretsUser
    }
  }
]

output vaultName string = vault.name
output vaultUri string = vault.properties.vaultUri
output signingKeyId string = signingKey.id
// URI sin versión: el código resuelve la versión vigente y la usa como `kid` (rotación, ADR-0008).
output signingKeyUri string = signingKey.properties.keyUri
