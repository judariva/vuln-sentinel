// Requisitos de plataforma (gate). NO lo ejecuta el pipeline del producto ni ninguna sesión: lo
// ejecuta el programa de la plataforma con aprobación de Juan (CLAUDE.md, «Gate de plataforma»).
// Está en el repo para que el requisito sea revisable y reproducible.
//
// Un solo paso (T9b): RG (G-1), identidades de los componentes del producto, identidad OIDC del
// pipeline con RBAC con condición limitada a esas identidades (G-2, ADR-0014), DCR y tabla del
// latido con el rol de publicación para los jobs (G-7) y presupuesto (G-9). Como las identidades
// las crea la plataforma, sus principalId se conocen aquí: ya no hace falta un segundo paso tras
// el primer despliegue del producto.
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

// Componentes que reciben roles del pipeline (main.bicep): App Insights (api y jobs), clave de
// firma (publish), secretos (cloudflared, ingest, investigate, publish) y Foundry (investigate,
// publish). `migrate` no recibe ningún rol de Azure (administra PostgreSQL por Entra ID): queda
// fuera de la condición.
var roleHolders = ['api', 'cloudflared', 'ingest', 'investigate', 'publish', 'daily']

// Jobs que escriben el latido en la DCR.
var heartbeatPublishers = ['ingest', 'investigate', 'publish', 'daily']

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

// Identidades de los componentes: el mismo módulo que usaba main.bicep, ahora en la plataforma.
// main.bicep las referencia por nombre (`identityNames`, por defecto `<prefijo>-id-<componente>`).
module productIds '../modules/identities.bicep' = {
  name: 'vs-product-identities'
  scope: productRg
  params: {
    location: location
    namePrefix: namePrefix
    tags: tags
  }
}

module pipeline 'modules/pipeline-identity.bicep' = {
  name: 'vs-pipeline-identity'
  scope: productRg
  params: {
    location: location
    namePrefix: namePrefix
    githubRepository: githubRepository
    githubEnvironment: githubEnvironment
    assignablePrincipalIds: map(
      filter(productIds.outputs.identities, x => contains(roleHolders, x.component)),
      x => x.principalId
    )
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
    publisherPrincipalIds: map(
      filter(productIds.outputs.identities, x => contains(heartbeatPublishers, x.component)),
      x => x.principalId
    )
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
