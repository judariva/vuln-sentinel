// Parámetros de ejemplo. VALORES FICTICIOS: ningún nombre, rango, ID ni dominio real (regla 8).
// En el pipeline, cada valor real llega por una variable de entorno que rellena `deploy.yml`
// desde las variables y secrets del entorno `prod` de GitHub. Sin la variable, queda el valor
// ficticio, que sirve para compilar y validar la plantilla, no para desplegar.
using 'main.bicep'

param namePrefix = readEnvironmentVariable('VS_NAME_PREFIX', 'vsdemo')

param tags = {
  product: 'vuln-sentinel'
  environment: 'prod'
}

// Red privada de ejemplo (RFC 1918, ficticia).
param vnetAddressPrefix = readEnvironmentVariable('VS_VNET_CIDR', '10.0.0.0/22')
param acaSubnetPrefix = readEnvironmentVariable('VS_SUBNET_ACA_CIDR', '10.0.0.0/27')
param postgresSubnetPrefix = readEnvironmentVariable('VS_SUBNET_PG_CIDR', '10.0.1.0/28')
param privateEndpointSubnetPrefix = readEnvironmentVariable('VS_SUBNET_PE_CIDR', '10.0.2.0/28')

// Imágenes fijadas por digest. El digest ficticio de ceros no existe: el pipeline pasa el real.
param image = readEnvironmentVariable(
  'VS_IMAGE',
  'ghcr.io/example/vuln-sentinel@sha256:0000000000000000000000000000000000000000000000000000000000000000'
)
param cloudflaredImage = readEnvironmentVariable(
  'VS_CLOUDFLARED_IMAGE',
  'docker.io/cloudflare/cloudflared@sha256:0000000000000000000000000000000000000000000000000000000000000000'
)

// Nombres de los secretos en el Key Vault del producto (los valores no pasan por aquí). Vacío =
// el secreto aún no existe y lo que depende de él no se despliega.
param tunnelTokenSecretName = readEnvironmentVariable('VS_KV_SECRET_TUNNEL', '')
param githubTokenSecretName = readEnvironmentVariable('VS_KV_SECRET_GITHUB', '')
param r2TokenSecretName = readEnvironmentVariable('VS_KV_SECRET_R2', '')

// Latido (G-7): salidas del despliegue de plataforma. Vacío = sin latido.
param heartbeatIngestionEndpoint = readEnvironmentVariable('VS_HEARTBEAT_ENDPOINT', '')
param heartbeatDcrImmutableId = readEnvironmentVariable('VS_HEARTBEAT_DCR_ID', '')

// Foundry (G-6). Vacío hasta que exista.
param foundryAccountName = readEnvironmentVariable('VS_FOUNDRY_ACCOUNT', '')

// PostgreSQL solo con Entra ID (sin contraseña).
param postgresPasswordAuth = false
