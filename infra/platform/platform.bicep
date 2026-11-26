// Requisitos de plataforma (gate). NO lo ejecuta el pipeline del producto ni ninguna sesión: lo
// ejecuta el programa de la plataforma con aprobación de Juan (CLAUDE.md, «Gate de plataforma»).
// Está en el repo para que el requisito sea revisable y reproducible.
//
// Dos pasos:
//   1. Sin publisherPrincipalIds: RG (G-1), identidad OIDC del pipeline con RBAC con condición
//      (G-2), DCR y tabla del latido (G-7) y presupuesto (G-9).
//   2. Tras el primer despliegue del producto: se repite con los principalId que da main.bicep,
//      para el rol de publicación en la DCR.
//
// Fuera de esta plantilla: reglas de Sentinel (G-7), SentinelHealth y grupo de acciones (G-8),
// Cost Management Reader para el job diario (G-17), Foundry (G-6), Cloudflare (G-10, G-11, G-15).

targetScope = 'subscription'

param location string = 'swedencentral'
param namePrefix string

@description('Nombre del RG del producto (G-1).')
param productResourceGroupName string

@description('RG del workspace de Sentinel de la plataforma.')
param sentinelResourceGroupName string

@description('Nombre del workspace de Sentinel.')
param sentinelWorkspaceName string

param githubRepository string
param githubEnvironment string = 'prod'

param publisherPrincipalIds array = []

param budgetAmount int = 80
param budgetStartDate string
param budgetContactEmails array = []
param budgetActionGroupIds array = []

param tags object = {}

resource productRg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: productResourceGroupName
  location: location
  tags: tags
}

module pipeline 'modules/pipeline-identity.bicep' = {
  name: 'vs-pipeline-identity'
  scope: productRg
  params: {
    location: location
    namePrefix: namePrefix
    githubRepository: githubRepository
    githubEnvironment: githubEnvironment
    tags: tags
  }
}

module heartbeat 'modules/heartbeat.bicep' = {
  name: 'vs-heartbeat'
  scope: resourceGroup(sentinelResourceGroupName)
  params: {
    location: location
    namePrefix: namePrefix
    workspaceName: sentinelWorkspaceName
    publisherPrincipalIds: publisherPrincipalIds
    tags: tags
  }
}

module budget 'modules/budget.bicep' = {
  name: 'vs-budget'
  scope: productRg
  params: {
    amount: budgetAmount
    startDate: budgetStartDate
    contactEmails: budgetContactEmails
    actionGroupIds: budgetActionGroupIds
  }
}

output pipelineClientId string = pipeline.outputs.clientId
output heartbeatIngestionEndpoint string = heartbeat.outputs.ingestionEndpoint
output heartbeatDcrImmutableId string = heartbeat.outputs.dcrImmutableId
