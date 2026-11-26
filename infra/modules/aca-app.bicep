// Container App genérica: la API (CMP-002, ingress interno) y cloudflared (CMP-010, sin ingress).
// Nunca con ingress externo: el entorno es interno y al origen solo se llega por el Tunnel
// (ADR-0004, CTL-008).

param location string
param name string
param environmentId string

@description('Identidad gestionada asignada por el usuario: { id, clientId }.')
param identity object

param image string
param command array = []
param args array = []

@description('Puerto del ingress interno. 0 = sin ingress.')
param targetPort int = 0

param minReplicas int = 0
param maxReplicas int = 1
param cpu string = '0.25'
param memory string = '0.5Gi'

@description('Variables de entorno: [{ name, value } | { name, secretRef }].')
param env array = []

@description('Secretos por referencia a Key Vault: [{ name, keyVaultUrl }].')
param keyVaultSecrets array = []

param tags object = {}

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    environmentId: environmentId
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: targetPort > 0
        ? {
            external: false
            targetPort: targetPort
            transport: 'http'
            allowInsecure: false
          }
        : null
      secrets: [
        for s in keyVaultSecrets: {
          name: s.name
          keyVaultUrl: s.keyVaultUrl
          identity: identity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'main'
          image: image
          command: empty(command) ? null : command
          args: empty(args) ? null : args
          env: concat(
            [
              {
                name: 'AZURE_CLIENT_ID'
                value: identity.clientId
              }
            ],
            env
          )
          resources: {
            cpu: json(cpu)
            memory: memory
          }
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
      }
    }
  }
}

output appName string = app.name
output fqdn string = targetPort > 0 ? app.properties.configuration.ingress.fqdn : ''
