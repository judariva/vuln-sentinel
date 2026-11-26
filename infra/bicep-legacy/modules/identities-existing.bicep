// Identidades del producto, ya creadas por la plataforma (infra/platform/, T9b). El pipeline no
// las crea: las referencia por nombre. Así sus principalId se conocen antes del primer despliegue y
// la condición ABAC del pipeline (ADR-0014) solo le deja asignar roles a ellas.

@description('Mapa componente → nombre de la identidad asignada por el usuario, en este RG.')
param identityNames object

var components = items(identityNames)

resource ids 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = [
  for c in components: {
    name: c.value
  }
]

// Misma forma que la salida de identities.bicep; main.bicep la convierte en un mapa.
output identities array = [
  for (c, i) in components: {
    component: c.key
    id: ids[i].id
    name: ids[i].name
    principalId: ids[i].properties.principalId
    clientId: ids[i].properties.clientId
  }
]
