// Parámetros de ejemplo de la plataforma. VALORES FICTICIOS (regla 8): los reales los pone el
// programa de la plataforma fuera del repo.
using 'platform.bicep'

param namePrefix = readEnvironmentVariable('VS_NAME_PREFIX', 'vsdemo')
param productResourceGroupName = readEnvironmentVariable('VS_RESOURCE_GROUP', 'rg-vsdemo')
param sentinelResourceGroupName = readEnvironmentVariable('VS_SENTINEL_RG', 'rg-sentinel-demo')
param sentinelWorkspaceName = readEnvironmentVariable('VS_SENTINEL_WORKSPACE', 'law-sentinel-demo')
param githubRepository = readEnvironmentVariable('VS_GITHUB_REPOSITORY', 'example/vuln-sentinel')
param budgetStartDate = readEnvironmentVariable('VS_BUDGET_START', '2027-01-01')

param tags = {
  product: 'vuln-sentinel'
  environment: 'prod'
}
