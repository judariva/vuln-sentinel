// Alerta de presupuesto (G-9, §14): 80 € al mes sobre el coste real del RG. Vale igual con pago
// por uso (ADR-0015). Los destinatarios llegan por parámetro: ningún correo en git.

@description('Importe mensual en la moneda de facturación.')
param amount int = 80

@description('Primer día del mes desde el que rige (AAAA-MM-01).')
param startDate string

@description('Correos que reciben la alerta. Nunca en git.')
param contactEmails array = []

@description('Grupos de acciones (correo y ntfy, G-8).')
param actionGroupIds array = []

resource budget 'Microsoft.Consumption/budgets@2023-11-01' = {
  name: 'vuln-sentinel-monthly'
  properties: {
    category: 'Cost'
    amount: amount
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: startDate
    }
    notifications: {
      actual80: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 80
        thresholdType: 'Actual'
        contactEmails: contactEmails
        contactGroups: actionGroupIds
      }
      actual100: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Actual'
        contactEmails: contactEmails
        contactGroups: actionGroupIds
      }
      forecast100: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: contactEmails
        contactGroups: actionGroupIds
      }
    }
  }
}
