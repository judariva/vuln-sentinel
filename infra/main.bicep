// vuln-sentinel · núcleo en Azure (PLAN §2, D9). Se despliega en el RG del producto (G-1) con el
// workflow manual `deploy.yml` (OIDC, entorno `prod` con aprobación). Esta sesión no despliega.
//
// Lo que NO está aquí, porque cambia el tenant fuera del RG o lo ejecuta la plataforma (gate):
// identidad OIDC del pipeline y su RBAC con condición (G-2, ADR-0014), DCR y tabla del latido en
// el workspace de Sentinel (G-7), alerta de presupuesto (G-9). Están en `infra/platform/`.
//
// Regla 8: ningún nombre, rango, ID ni correo real en el repo. Todo llega por parámetro desde las
// variables del pipeline (`main.bicepparam` las lee con readEnvironmentVariable).

targetScope = 'resourceGroup'

@description('Región (ADR-0001: Sweden Central).')
param location string = resourceGroup().location

@description('Prefijo de nombres de los recursos.')
@minLength(2)
@maxLength(10)
param namePrefix string

@description('Etiquetas comunes.')
param tags object = {}

// --- Red (G-4) ---
param vnetAddressPrefix string
param acaSubnetPrefix string
param postgresSubnetPrefix string
param privateEndpointSubnetPrefix string

// --- Imágenes ---
@description('Imagen del producto, fijada por digest (ghcr.io/<owner>/vuln-sentinel@sha256:...).')
param image string

@description('Imagen de cloudflared, fijada por digest.')
param cloudflaredImage string

@description('Módulo de Python que ejecuta cada componente (ENTRYPOINT `python -m`). Los puntos de entrada de los jobs llegan en F1a.')
param entrypoints object = {
  api: 'vs.api.serve'
  ingest: 'vs.jobs.ingest'
  investigate: 'vs.jobs.investigate'
  publish: 'vs.jobs.publish'
  daily: 'vs.jobs.daily'
}

// --- Jobs (ADR-0002). Cron en UTC: ACA no admite zona horaria. ---
param cronIngest string = '*/5 * * * *'
param cronInvestigate string = '*/10 * * * *'
param cronPublish string = '*/10 * * * *'

@description('Resumen diario a las 07:00 Europe/Madrid (§12). 05:00 UTC = 07:00 en verano y 06:00 en invierno: nunca después de las 07:00.')
param cronDaily string = '0 5 * * *'

// --- Secretos de Key Vault (los valores los pone la plataforma o Juan, con caducidad, G-5) ---
// El vault no tiene acceso público: los secretos se crean por ARM (recurso
// Microsoft.KeyVault/vaults/secrets con parámetro seguro), no por el plano de datos.
@description('Secreto con el token del Tunnel (G-11). Vacío = cloudflared aún no se despliega (primer despliegue, antes de que exista el secreto).')
param tunnelTokenSecretName string = ''

@description('Secreto con el token de GitHub de solo lectura para la ingesta. Vacío = sin token.')
param githubTokenSecretName string = ''

@description('Secreto con el token de R2 limitado al bucket (G-15). Vacío = aún no.')
param r2TokenSecretName string = ''

// --- Latido (G-7): DCR en el workspace de Sentinel, creada por la plataforma ---
@description('Endpoint de la Logs Ingestion API (DCR de tipo Direct o DCE). Vacío = sin latido.')
param heartbeatIngestionEndpoint string = ''

@description('immutableId de la DCR del latido.')
param heartbeatDcrImmutableId string = ''

param heartbeatStreamName string = 'Custom-VsHeartbeat_CL'

// --- IA (ADR-0009, condicionado a G-6) ---
@description('Nombre de la cuenta de Foundry (AI Services) en este RG. Vacío = aún no existe (G-6).')
param foundryAccountName string = ''

// --- PostgreSQL ---
param postgresPasswordAuth bool = false
param postgresAdministratorLogin string = ''
@secure()
param postgresAdministratorPassword string = ''

param keyVaultPurgeProtection bool = true

var suffix = take(uniqueString(resourceGroup().id), 6)

var roleMetricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb' // Monitoring Metrics Publisher
var roleCognitiveServicesUser = 'a97b65f3-24c7-4388-baec-2e87135dc908' // Cognitive Services User

module network 'modules/network.bicep' = {
  name: 'network'
  params: {
    location: location
    namePrefix: namePrefix
    vnetAddressPrefix: vnetAddressPrefix
    acaSubnetPrefix: acaSubnetPrefix
    postgresSubnetPrefix: postgresSubnetPrefix
    privateEndpointSubnetPrefix: privateEndpointSubnetPrefix
    tags: tags
  }
}

module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  params: {
    location: location
    namePrefix: namePrefix
    tags: tags
  }
}

module ids 'modules/identities.bicep' = {
  name: 'identities'
  params: {
    location: location
    namePrefix: namePrefix
    tags: tags
  }
}

var id = toObject(ids.outputs.identities, x => x.component)

// Quién lee qué secreto (alcance: el secreto, no el vault).
var secretReaders = concat(
  empty(tunnelTokenSecretName)
    ? []
    : [{ secret: tunnelTokenSecretName, principalIds: [id.cloudflared.principalId] }],
  empty(githubTokenSecretName)
    ? []
    : [{ secret: githubTokenSecretName, principalIds: [id.ingest.principalId, id.investigate.principalId] }],
  empty(r2TokenSecretName) ? [] : [{ secret: r2TokenSecretName, principalIds: [id.publish.principalId] }]
)

module kv 'modules/keyvault.bicep' = {
  name: 'keyvault'
  params: {
    location: location
    namePrefix: namePrefix
    uniqueSuffix: suffix
    privateEndpointSubnetId: network.outputs.privateEndpointSubnetId
    keyVaultDnsZoneId: network.outputs.keyVaultDnsZoneId
    signerPrincipalIds: [id.publish.principalId]
    secretReaders: secretReaders
    enablePurgeProtection: keyVaultPurgeProtection
    tags: tags
  }
}

module pg 'modules/postgres.bicep' = {
  name: 'postgres'
  params: {
    location: location
    namePrefix: namePrefix
    uniqueSuffix: suffix
    delegatedSubnetId: network.outputs.postgresSubnetId
    privateDnsZoneId: network.outputs.postgresDnsZoneId
    entraAdmin: {
      principalId: id.migrate.principalId
      name: id.migrate.name
    }
    passwordAuth: postgresPasswordAuth
    administratorLogin: postgresAdministratorLogin
    administratorLoginPassword: postgresAdministratorPassword
    tags: tags
  }
}

module env 'modules/aca-env.bicep' = {
  name: 'aca-env'
  params: {
    location: location
    namePrefix: namePrefix
    infrastructureSubnetId: network.outputs.acaSubnetId
    logAnalyticsWorkspaceName: monitoring.outputs.workspaceName
    tags: tags
  }
}

// Trazas OTel: cada identidad que emite publica en App Insights con Entra ID (sin clave local).
resource appInsights 'Microsoft.Insights/components@2020-02-02' existing = {
  name: '${namePrefix}-appi'
}

var tracers = ['api', 'ingest', 'investigate', 'publish', 'daily']

resource tracerRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for c in tracers: {
    name: guid(resourceGroup().id, '${namePrefix}-appi', c, roleMetricsPublisher)
    scope: appInsights
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleMetricsPublisher)
      principalId: id[c].principalId
      principalType: 'ServicePrincipal'
    }
    dependsOn: [
      monitoring
    ]
  }
]

// Claude en Foundry (ADR-0009): solo el job investigate y, para redactar, publish.
resource foundry 'Microsoft.CognitiveServices/accounts@2024-10-01' existing = if (!empty(foundryAccountName)) {
  name: empty(foundryAccountName) ? 'none' : foundryAccountName
}

resource foundryRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for c in (empty(foundryAccountName) ? [] : ['investigate', 'publish']): {
    name: guid(resourceGroup().id, foundryAccountName, c, roleCognitiveServicesUser)
    scope: foundry
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleCognitiveServicesUser)
      principalId: id[c].principalId
      principalType: 'ServicePrincipal'
    }
  }
]

// Variables comunes. La conexión a PostgreSQL es con token de Entra ID (sin contraseña): el
// usuario de base de datos es el nombre de la identidad de cada componente.
var commonEnv = concat(
  [
    { name: 'VS_DATABASE_HOST', value: pg.outputs.fqdn }
    { name: 'VS_DATABASE_NAME', value: pg.outputs.databaseName }
    { name: 'VS_DATABASE_AUTH', value: 'entra' }
    { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: monitoring.outputs.appInsightsConnectionString }
    { name: 'APPLICATIONINSIGHTS_AUTHENTICATION_STRING', value: 'Authorization=AAD' }
  ],
  empty(heartbeatIngestionEndpoint)
    ? []
    : [
        { name: 'VS_HEARTBEAT_ENDPOINT', value: heartbeatIngestionEndpoint }
        { name: 'VS_HEARTBEAT_DCR_ID', value: heartbeatDcrImmutableId }
        { name: 'VS_HEARTBEAT_STREAM', value: heartbeatStreamName }
      ]
)

var githubSecret = empty(githubTokenSecretName)
  ? []
  : [{ name: 'github-token', keyVaultUrl: '${kv.outputs.vaultUri}secrets/${githubTokenSecretName}' }]
var githubEnv = empty(githubTokenSecretName) ? [] : [{ name: 'VS_GITHUB_TOKEN', secretRef: 'github-token' }]

var r2Secret = empty(r2TokenSecretName)
  ? []
  : [{ name: 'r2-token', keyVaultUrl: '${kv.outputs.vaultUri}secrets/${r2TokenSecretName}' }]
var r2Env = empty(r2TokenSecretName) ? [] : [{ name: 'VS_R2_TOKEN', secretRef: 'r2-token' }]

// --- API (CMP-002): ingress interno, escala 0–1 ---
module api 'modules/aca-app.bicep' = {
  name: 'app-api'
  params: {
    location: location
    name: '${namePrefix}-api'
    environmentId: env.outputs.environmentId
    identity: id.api
    image: image
    args: [entrypoints.api]
    targetPort: 8000
    minReplicas: 0
    maxReplicas: 1
    env: concat(commonEnv, [{ name: 'VS_DATABASE_USER', value: id.api.name }])
    tags: tags
  }
}

// --- cloudflared (CMP-010): una réplica fija, sin ingress, token del Tunnel desde Key Vault ---
module tunnel 'modules/aca-app.bicep' = if (!empty(tunnelTokenSecretName)) {
  name: 'app-cloudflared'
  params: {
    location: location
    name: '${namePrefix}-cloudflared'
    environmentId: env.outputs.environmentId
    identity: id.cloudflared
    image: cloudflaredImage
    args: ['tunnel', '--no-autoupdate', 'run']
    minReplicas: 1
    maxReplicas: 1
    keyVaultSecrets: [
      { name: 'tunnel-token', keyVaultUrl: '${kv.outputs.vaultUri}secrets/${tunnelTokenSecretName}' }
    ]
    // La referencia a Key Vault se resuelve al crear la revisión: el rol tiene que existir antes.
    env: [
      { name: 'TUNNEL_TOKEN', secretRef: 'tunnel-token' }
    ]
    tags: tags
  }
}

// --- Jobs (CMP-003…CMP-006) ---
module jobIngest 'modules/aca-job.bicep' = {
  name: 'job-ingest'
  params: {
    location: location
    name: '${namePrefix}-ingest'
    environmentId: env.outputs.environmentId
    identity: id.ingest
    image: image
    args: [entrypoints.ingest]
    cronExpression: cronIngest
    replicaTimeout: 280
    keyVaultSecrets: githubSecret
    env: concat(commonEnv, githubEnv, [{ name: 'VS_DATABASE_USER', value: id.ingest.name }])
    tags: tags
  }
}

module jobInvestigate 'modules/aca-job.bicep' = {
  name: 'job-investigate'
  params: {
    location: location
    name: '${namePrefix}-investigate'
    environmentId: env.outputs.environmentId
    identity: id.investigate
    image: image
    args: [entrypoints.investigate]
    cronExpression: cronInvestigate
    replicaTimeout: 580
    keyVaultSecrets: githubSecret
    env: concat(commonEnv, githubEnv, [{ name: 'VS_DATABASE_USER', value: id.investigate.name }])
    tags: tags
  }
}

module jobPublish 'modules/aca-job.bicep' = {
  name: 'job-publish'
  params: {
    location: location
    name: '${namePrefix}-publish'
    environmentId: env.outputs.environmentId
    identity: id.publish
    image: image
    args: [entrypoints.publish]
    cronExpression: cronPublish
    replicaTimeout: 580
    keyVaultSecrets: r2Secret
    env: concat(commonEnv, r2Env, [
      { name: 'VS_DATABASE_USER', value: id.publish.name }
      { name: 'VS_SIGNING_KEY_URI', value: kv.outputs.signingKeyUri }
    ])
    tags: tags
  }
}

module jobDaily 'modules/aca-job.bicep' = {
  name: 'job-daily'
  params: {
    location: location
    name: '${namePrefix}-daily'
    environmentId: env.outputs.environmentId
    identity: id.daily
    image: image
    args: [entrypoints.daily]
    cronExpression: cronDaily
    replicaTimeout: 1200
    env: concat(commonEnv, [{ name: 'VS_DATABASE_USER', value: id.daily.name }])
    tags: tags
  }
}

// --- Migraciones: job manual. Su identidad es el administrador Entra de PostgreSQL; ningún otro
// componente ni el pipeline tienen acceso de administración a la BD. ---
module jobMigrate 'modules/aca-job.bicep' = {
  name: 'job-migrate'
  params: {
    location: location
    name: '${namePrefix}-migrate'
    environmentId: env.outputs.environmentId
    identity: id.migrate
    image: image
    args: ['vs.model.migrate', 'upgrade', 'head']
    replicaTimeout: 900
    env: concat(commonEnv, [{ name: 'VS_DATABASE_USER', value: id.migrate.name }])
    tags: tags
  }
}

// Salidas sin secretos. La plataforma usa los principalId para G-7 (rol de publicación en la DCR)
// y G-17 (Cost Management Reader para el job diario).
output principalIds object = {
  ingest: id.ingest.principalId
  investigate: id.investigate.principalId
  publish: id.publish.principalId
  daily: id.daily.principalId
}
output keyVaultName string = kv.outputs.vaultName
output signingKeyUri string = kv.outputs.signingKeyUri
output migrateJobName string = jobMigrate.outputs.jobName
output apiInternalFqdn string = api.outputs.fqdn
