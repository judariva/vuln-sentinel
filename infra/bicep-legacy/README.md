# infra/bicep-legacy — referencia, no se despliega

Bicep del núcleo en Azure de T9 y T9b. **Queda como referencia de diseño y no se despliega ni se
compila en la CI.** Lo sustituye el módulo Terraform `infra/terraform/modules/vuln-sentinel/`,
que despliega la factoría de la plataforma (ADR-0025).

| Fichero | Qué era | Dónde está ahora |
|---|---|---|
| `main.bicep`, `main.bicepparam`, `modules/` | Núcleo del producto en el RG | `infra/terraform/modules/vuln-sentinel/` |
| `modules/network.bicep` | VNet, subredes y zonas DNS privadas | Landing zone de la plataforma (entradas del módulo) |
| `modules/monitoring.bicep` | Log Analytics y App Insights propios | Workspace de la plataforma (entrada); App Insights opcional |
| `modules/keyvault.bicep` | Key Vault, clave de firma y roles | Vault del landing zone; la clave la crea el módulo; los roles, el vending |
| `modules/identities*.bicep` | Identidades por componente | Vending de la plataforma |
| `platform/` | Gate de plataforma: identidades, pipeline OIDC con condición (ADR-0014), latido, presupuesto | Vending de la plataforma |
| `platform/modules/heartbeat.bicep` | DCR y tabla `VsHeartbeat_CL` | La crea la plataforma. **Sigue siendo el esquema de referencia de la tabla**: `tests/test_heartbeat.py` contrasta las columnas del latido con este fichero |
| `scripts/az-quiet.sh` | Envoltorio de `az` que solo enseña códigos de error | Sin uso; sus tests se conservan |
| `workflows/deploy.yml` | Despliegue manual con OIDC y what-if | Retirado: despliega la factoría de la plataforma. Fuera de `.github/workflows/`, así que no se ejecuta |

Las referencias de rutas dentro de estos ficheros (`infra/main.bicep`, `infra/scripts/…`) son las
de antes del traslado.
