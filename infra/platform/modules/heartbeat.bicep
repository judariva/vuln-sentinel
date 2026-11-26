// Latido (G-7, CMP-012, CTL-009): tabla VsHeartbeat_CL en el workspace de Sentinel de la
// plataforma, DCR de tipo Direct (con su propio endpoint de la Logs Ingestion API) y rol de
// publicación SOBRE LA DCR para las identidades de los jobs. Se despliega en el RG del workspace,
// por eso lo ejecuta la plataforma y no el pipeline del producto.
//
// Esquema propuesto en T9 (las 3 reglas de §11 lo necesitan):
//   Job            ingest | investigate | publish | daily
//   RunId          identificador de la ejecución
//   Outcome        ok | partial | failed
//   StartedAt      inicio de la ejecución
//   DurationMs     duración
//   UnknownSources [{ source, since }] fuentes en UNKNOWN y desde cuándo (regla «> 2 h»)
//   AiCostUsdToday coste de IA acumulado del día (regla «> 80 % del tope»)
//   Version        versión o digest de la imagen

param location string

@description('Nombre del workspace de Sentinel (existente, en este RG).')
param workspaceName string

param namePrefix string

@description('principalId de las identidades de los jobs (las crea platform.bicep, T9b).')
param publisherPrincipalIds array = []

param tags object = {}

var tableName = 'VsHeartbeat_CL'
var streamName = 'Custom-${tableName}'
var roleMetricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb'

var columns = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'Job', type: 'string' }
  { name: 'RunId', type: 'string' }
  { name: 'Outcome', type: 'string' }
  { name: 'StartedAt', type: 'datetime' }
  { name: 'DurationMs', type: 'long' }
  { name: 'UnknownSources', type: 'dynamic' }
  { name: 'AiCostUsdToday', type: 'real' }
  { name: 'Version', type: 'string' }
]

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspace
  name: tableName
  properties: {
    plan: 'Analytics'
    retentionInDays: 30
    schema: {
      name: tableName
      columns: columns
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${namePrefix}-dcr-heartbeat'
  location: location
  tags: tags
  kind: 'Direct'
  properties: {
    streamDeclarations: {
      '${streamName}': {
        columns: columns
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'sentinel'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          streamName
        ]
        destinations: [
          'sentinel'
        ]
        transformKql: 'source'
        outputStream: streamName
      }
    ]
  }
  dependsOn: [
    table
  ]
}

resource publishers 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for p in publisherPrincipalIds: {
    name: guid(dcr.id, p, roleMetricsPublisher)
    scope: dcr
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleMetricsPublisher)
      principalId: p
      principalType: 'ServicePrincipal'
    }
  }
]

// Van a las variables VS_HEARTBEAT_ENDPOINT y VS_HEARTBEAT_DCR_ID del entorno `prod`.
output ingestionEndpoint string = dcr.properties.endpoints.logsIngestion
output dcrImmutableId string = dcr.properties.immutableId
output streamName string = streamName
