// Container Apps Job genérico (CMP-003…CMP-006 y migrate). Con cron o manual. Todos usan la
// misma imagen; cambia el módulo que ejecutan (`python -m <módulo>`).
// El reparto de trabajo y la exclusión mutua van en la BD (FOR UPDATE SKIP LOCKED, ADR-0002):
// si una ejecución se solapa con la anterior, no se pisan.

param location string
param name string
param environmentId string

@description('Identidad gestionada asignada por el usuario: { id, clientId }.')
param identity object

param image string

@description('Argumentos del contenedor (el ENTRYPOINT de la imagen es `python -m`).')
param args array

@description('Expresión cron en UTC. Vacía = job manual.')
param cronExpression string = ''

@description('Tiempo máximo por ejecución, en segundos.')
param replicaTimeout int = 600

@description('Reintentos por ejecución.')
param replicaRetryLimit int = 0

param cpu string = '0.25'
param memory string = '0.5Gi'

@description('Variables de entorno: [{ name, value } | { name, secretRef }].')
param env array = []

@description('Secretos por referencia a Key Vault: [{ name, keyVaultUrl }]. Se leen con la identidad del job.')
param keyVaultSecrets array = []

param tags object = {}

var scheduled = !empty(cronExpression)

resource job 'Microsoft.App/jobs@2024-03-01' = {
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
      triggerType: scheduled ? 'Schedule' : 'Manual'
      scheduleTriggerConfig: scheduled
        ? {
            cronExpression: cronExpression
            parallelism: 1
            replicaCompletionCount: 1
          }
        : null
      manualTriggerConfig: scheduled
        ? null
        : {
            parallelism: 1
            replicaCompletionCount: 1
          }
      replicaTimeout: replicaTimeout
      replicaRetryLimit: replicaRetryLimit
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
          args: args
          env: concat(
            [
              {
                // Para DefaultAzureCredential / ManagedIdentityCredential con identidad de usuario.
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
    }
  }
}

output jobName string = job.name
