// PostgreSQL Flexible Server B1ms con acceso privado (CMP-007, ADR-0003).
// - Subred delegada y zona DNS privada: sin acceso público.
// - Autenticación: Entra ID por defecto, sin contraseña. El administrador Entra es la identidad
//   del job `migrate`; los demás componentes entran con su identidad y los roles de base de datos
//   que les dé la migración. La autenticación por contraseña queda detrás de un parámetro
//   (pregunta abierta del informe de T9) y su valor llegaría solo como parámetro seguro.

param location string
param namePrefix string
param uniqueSuffix string

param delegatedSubnetId string
param privateDnsZoneId string

@description('Versión mayor de PostgreSQL (la CI usa 17).')
param postgresVersion string = '17'

@description('Almacenamiento en GB.')
param storageSizeGB int = 32

@description('Retención de backups en días (incluidos en el precio hasta el tamaño del disco).')
@minValue(7)
param backupRetentionDays int = 7

@description('Administrador Entra: identidad gestionada del job migrate.')
param entraAdmin object

@description('Autenticación por contraseña. Por defecto desactivada (solo Entra ID).')
param passwordAuth bool = false

@description('Usuario administrador si passwordAuth = true.')
param administratorLogin string = ''

@secure()
@description('Contraseña del administrador si passwordAuth = true. Nunca en git.')
param administratorLoginPassword string = ''

param databaseName string = 'vulnsentinel'
param tags object = {}

resource server 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: '${namePrefix}-pg-${uniqueSuffix}'
  location: location
  tags: tags
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    version: postgresVersion
    storage: {
      storageSizeGB: storageSizeGB
      autoGrow: 'Disabled'
    }
    backup: {
      backupRetentionDays: backupRetentionDays
      geoRedundantBackup: 'Disabled'
    }
    highAvailability: {
      mode: 'Disabled'
    }
    network: {
      delegatedSubnetResourceId: delegatedSubnetId
      privateDnsZoneArmResourceId: privateDnsZoneId
      publicNetworkAccess: 'Disabled'
    }
    authConfig: {
      activeDirectoryAuth: 'Enabled'
      passwordAuth: passwordAuth ? 'Enabled' : 'Disabled'
      tenantId: subscription().tenantId
    }
    administratorLogin: passwordAuth ? administratorLogin : null
    administratorLoginPassword: passwordAuth ? administratorLoginPassword : null
  }
}

resource admin 'Microsoft.DBforPostgreSQL/flexibleServers/administrators@2024-08-01' = {
  parent: server
  name: entraAdmin.principalId
  properties: {
    principalType: 'ServicePrincipal'
    principalName: entraAdmin.name
    tenantId: subscription().tenantId
  }
}

// TLS obligatorio (por defecto ya está activo; se fija para que no dependa del valor por defecto).
resource requireTls 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2024-08-01' = {
  parent: server
  name: 'require_secure_transport'
  properties: {
    value: 'on'
    source: 'user-override'
  }
  dependsOn: [
    admin
  ]
}

resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: server
  name: databaseName
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
  dependsOn: [
    requireTls
  ]
}

output serverName string = server.name
output fqdn string = server.properties.fullyQualifiedDomainName
output databaseName string = database.name
