// Una identidad gestionada asignada por el usuario por componente (G-2). Asignadas por el
// usuario, y no por el sistema, para que existan y tengan sus roles ANTES de crear la app o el
// job: así las referencias a Key Vault resuelven en el primer arranque.
//
// La despliega la plataforma (infra/platform/platform.bicep, T9b), no el pipeline: sus principalId
// entran en la condición ABAC del pipeline (ADR-0014). main.bicep las referencia con
// identities-existing.bicep.

param location string
param namePrefix string
param tags object = {}

@description('Componentes con identidad propia.')
param components array = [
  'api'
  'cloudflared'
  'ingest'
  'investigate'
  'publish'
  'daily'
  'migrate'
]

resource ids 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = [
  for c in components: {
    name: '${namePrefix}-id-${c}'
    location: location
    tags: tags
  }
]

// Lista de identidades; main.bicep la convierte en un mapa componente → identidad.
output identities array = [
  for (c, i) in components: {
    component: c
    id: ids[i].id
    name: ids[i].name
    principalId: ids[i].properties.principalId
    clientId: ids[i].properties.clientId
  }
]
