// Identidad del pipeline (G-2, ADR-0014, CTL-010):
// - identidad gestionada con credencial federada OIDC de GitHub, solo para el entorno `prod`
//   del repo (sin secretos de cliente). La rama `main` se impone con la regla de despliegue del
//   entorno en GitHub;
// - Contributor sobre el RG del producto;
// - Role Based Access Control Administrator sobre el RG CON CONDICIÓN: solo puede asignar o quitar
//   los roles de la lista y solo a principales de tipo ServicePrincipal. No puede darse Owner,
//   User Access Administrator ni ningún otro rol.

param location string
param namePrefix string

@description('Repositorio de GitHub «propietario/repo». Llega por parámetro, no se escribe en git.')
param githubRepository string

@description('Entorno de GitHub con aprobación desde el que se despliega.')
param githubEnvironment string = 'prod'

@description('GUID de los roles que el pipeline puede asignar a las identidades del RG.')
param assignableRoleIds array = [
  '12338af0-0e69-4776-bea7-57ae8d297424' // Key Vault Crypto User
  '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User
  'a97b65f3-24c7-4388-baec-2e87135dc908' // Cognitive Services User
  '3913510d-42f4-4e42-8a64-420c390055eb' // Monitoring Metrics Publisher
]

param tags object = {}

var roleContributor = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
var roleRbacAdmin = 'f58310d9-a9f6-439a-9e8d-f62e7b41a168' // Role Based Access Control Administrator

resource pipeline 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id-pipeline'
  location: location
  tags: tags
}

resource federation 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  parent: pipeline
  name: 'github-${githubEnvironment}'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    subject: 'repo:${githubRepository}:environment:${githubEnvironment}'
    audiences: [
      'api://AzureADTokenExchange'
    ]
  }
}

resource contributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, pipeline.id, roleContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleContributor)
    principalId: pipeline.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

var roleList = join(assignableRoleIds, ', ')

// Condición ABAC (v2.0): escribir y borrar asignaciones solo con un rol de la lista y a un
// ServicePrincipal. Cualquier otra acción del rol (leer) no se restringe.
var condition = '((!(ActionMatches{\'Microsoft.Authorization/roleAssignments/write\'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${roleList}} AND @Request[Microsoft.Authorization/roleAssignments:PrincipalType] ForAnyOfAnyValues:StringEqualsIgnoreCase {\'ServicePrincipal\'})) AND ((!(ActionMatches{\'Microsoft.Authorization/roleAssignments/delete\'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${roleList}} AND @Resource[Microsoft.Authorization/roleAssignments:PrincipalType] ForAnyOfAnyValues:StringEqualsIgnoreCase {\'ServicePrincipal\'}))'

resource rbacAdmin 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, pipeline.id, roleRbacAdmin)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleRbacAdmin)
    principalId: pipeline.properties.principalId
    principalType: 'ServicePrincipal'
    conditionVersion: '2.0'
    condition: condition
    description: 'vuln-sentinel: el pipeline solo asigna los roles de las identidades del RG (ADR-0014)'
  }
}

// El client-id va a la variable AZURE_CLIENT_ID del entorno `prod` de GitHub (no es un secreto,
// pero tampoco se escribe en git, regla 8).
output clientId string = pipeline.properties.clientId
output principalId string = pipeline.properties.principalId
