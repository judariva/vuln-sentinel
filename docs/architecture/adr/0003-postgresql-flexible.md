---
adr: "0003"
titulo: PostgreSQL Flexible Server B1ms con acceso privado
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-007]
sustituye: null
---

## Contexto

Modelo relacional con historial de señales y agregados diarios (D11).

## Decisión

Azure Database for PostgreSQL Flexible Server, Burstable B1ms, 32 GB, acceso privado.

## Alternativas descartadas

- Azure SQL serverless con oferta gratuita: la pausa automática (15 min) nunca salta con ingesta cada 5 min y la cuota se agota en días.
- Cosmos DB free tier: no relacional; agregados incómodos.

## Consecuencias

~17 €/mes con backups de 7 días incluidos. En la gama Burstable no hay backups bajo demanda.

## Evidencia

- https://prices.azure.com/api/retail/prices (2026-11-25)
- https://learn.microsoft.com/en-us/azure/azure-sql/database/free-offer (2026-11-25)
- https://learn.microsoft.com/en-us/azure/postgresql/backup-restore/concepts-backup-restore (2026-11-25)
