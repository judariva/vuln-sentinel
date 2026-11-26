// Observabilidad del producto: Log Analytics propio (logs del entorno de Container Apps) y
// Application Insights basado en ese workspace (trazas OTel GenAI, CMP-014).
// El latido NO va aquí: va al workspace de Sentinel de la plataforma (G-7, infra/platform/).

param location string
param namePrefix string

@description('Retención de Log Analytics en días.')
@minValue(30)
param retentionInDays int = 30

@description('Tope diario de ingesta en GB (control de coste, §14). -1 = sin tope.')
param dailyQuotaGb string = '0.2'

param tags object = {}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-log'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    workspaceCapping: {
      dailyQuotaGb: json(dailyQuotaGb)
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// Ingesta solo con Entra ID (DisableLocalAuth): la clave de instrumentación no basta para
// escribir. Cada identidad que emite trazas recibe Monitoring Metrics Publisher (G-2).
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${namePrefix}-appi'
  location: location
  tags: tags
  kind: 'other'
  properties: {
    Application_Type: 'other'
    WorkspaceResourceId: workspace.id
    DisableLocalAuth: true
    IngestionMode: 'LogAnalytics'
  }
}

output workspaceName string = workspace.name
output workspaceId string = workspace.id
output appInsightsName string = appInsights.name
output appInsightsConnectionString string = appInsights.properties.ConnectionString
