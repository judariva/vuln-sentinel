// Red del producto (G-4): VNet propia con tres subredes y las zonas DNS privadas.
// - aca: entorno de Container Apps con perfiles de carga (solo Consumption). Delegada a
//   Microsoft.App/environments; mínimo /27.
// - postgres: delegada a Microsoft.DBforPostgreSQL/flexibleServers (acceso privado, ADR-0003).
// - pe: endpoints privados (Key Vault).
// Los rangos llegan por parámetro (regla 8): nunca se escriben en el repo.

@description('Región de los recursos.')
param location string

@description('Prefijo de nombres (sin nombres reales de la plataforma en git).')
param namePrefix string

@description('Espacio de direcciones de la VNet.')
param vnetAddressPrefix string

@description('Rango de la subred del entorno de Container Apps (mínimo /27).')
param acaSubnetPrefix string

@description('Rango de la subred delegada de PostgreSQL.')
param postgresSubnetPrefix string

@description('Rango de la subred de endpoints privados.')
param privateEndpointSubnetPrefix string

param tags object = {}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${namePrefix}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [vnetAddressPrefix]
    }
    subnets: [
      {
        name: 'aca'
        properties: {
          addressPrefix: acaSubnetPrefix
          delegations: [
            {
              name: 'aca'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'postgres'
        properties: {
          addressPrefix: postgresSubnetPrefix
          delegations: [
            {
              name: 'postgres'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
        }
      }
      {
        name: 'pe'
        properties: {
          addressPrefix: privateEndpointSubnetPrefix
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}

// Zona privada de PostgreSQL. El nombre debe acabar en «.private.postgres.database.azure.com».
resource postgresDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: '${namePrefix}.private.postgres.database.azure.com'
  location: 'global'
  tags: tags
}

resource postgresDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: postgresDnsZone
  name: 'vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

// Zona privada de Key Vault (endpoint privado).
#disable-next-line no-hardcoded-env-urls
resource keyVaultDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
  tags: tags
}

resource keyVaultDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: keyVaultDnsZone
  name: 'vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

output vnetId string = vnet.id
output acaSubnetId string = vnet.properties.subnets[0].id
output postgresSubnetId string = vnet.properties.subnets[1].id
output privateEndpointSubnetId string = vnet.properties.subnets[2].id
output postgresDnsZoneId string = postgresDnsZone.id
output keyVaultDnsZoneId string = keyVaultDnsZone.id
