// Entorno de Container Apps (ADR-0002, ADR-0004):
// - perfiles de carga con SOLO el perfil Consumption (nada dedicado);
// - en la subred propia, interno: sin IP pública ni ingress externo. Al origen solo se llega
//   por el Tunnel (cloudflared corre dentro del entorno).
// - logs de las apps al Log Analytics propio.

param location string
param namePrefix string
param infrastructureSubnetId string
param logAnalyticsWorkspaceName string
param tags object = {}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logAnalyticsWorkspaceName
}

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${namePrefix}-cae'
  location: location
  tags: tags
  properties: {
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
    vnetConfiguration: {
      infrastructureSubnetId: infrastructureSubnetId
      internal: true
    }
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: workspace.properties.customerId
        sharedKey: workspace.listKeys().primarySharedKey
      }
    }
    zoneRedundant: false
  }
}

output environmentId string = env.id
output environmentName string = env.name
