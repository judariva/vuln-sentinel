# Vista de despliegue

Qué se despliega, dónde y quién lo escribe. Solo IDs de `architecture.yaml`; ningún nombre,
rango ni ID real (regla 8). Código: `infra/` (Bicep) y `.github/workflows/`.

## Quién escribe

| Paso | Quién | Qué |
|---|---|---|
| Plataforma (gate) | Programa de la plataforma, con aprobación de Juan | `infra/platform/platform.bicep`: RG (G-1), identidades de los componentes (CMP-026), identidad del pipeline con OIDC y RBAC Administrator con condición (G-2, CTL-010), DCR y tabla del latido en el workspace de Sentinel (G-7, CMP-012), presupuesto (G-9) |
| Imagen | CMP-028 (`images.yml`, al fusionar en `main`) | Imagen única en CMP-029, por digest (FLW-031), con SBOM y procedencia firmados (CTL-026) |
| Producto | CMP-028 (`deploy.yml`, manual, entorno `prod` con aprobación) | Verifica la procedencia de la imagen (CTL-026) y despliega `infra/main.bicep` en el RG del producto (FLW-032, CTL-020, CTL-021) |
| Sesión local | Nadie | Solo `az bicep build` y `az bicep lint` |

## Qué hay en el RG del producto

```
CMP-025 VNet propia ─┬─ subred aca (delegada)  ── entorno ACA, solo Consumption, interno
                     │                              ├─ CMP-002 api       (ingress interno, 0–1)
                     │                              ├─ CMP-010 cloudflared (1 réplica, sin ingress)
                     │                              ├─ CMP-003 ingest      cron */5
                     │                              ├─ CMP-004 investigate cron */10
                     │                              ├─ CMP-005 publish     cron */10
                     │                              ├─ CMP-006 daily       cron diario (UTC)
                     │                              └─ CMP-027 migrate     manual
                     ├─ subred postgres (delegada) ── CMP-007 PostgreSQL B1ms, sin acceso público
                     └─ subred pe ── endpoint privado ── CMP-008 Key Vault (RBAC, sin acceso público)
CMP-026 identidades (una por componente; las crea la plataforma, main.bicep las referencia)
CMP-030 Log Analytics propio ── CMP-014 App Insights (ingesta solo con Entra ID)
```

Fuera del RG: CMP-012 (workspace de Sentinel de la plataforma, solo la DCR y la tabla del
latido), CMP-009 (Foundry, pendiente de G-6), CMP-011 y CMP-016 (Cloudflare, G-10, G-11, G-15).

## Roles (CTL-019)

| Identidad | Rol | Alcance |
|---|---|---|
| publish | Key Vault Crypto User | la clave de firma (FLW-004) |
| cloudflared | Key Vault Secrets User | el secreto del token del Tunnel (FLW-034) |
| ingest, investigate | Key Vault Secrets User | el secreto del token de GitHub, si existe |
| publish | Key Vault Secrets User | el secreto del token de R2 (G-15), si existe |
| api, ingest, investigate, publish, daily | Monitoring Metrics Publisher | App Insights (FLW-036) |
| ingest, investigate, publish, daily | Monitoring Metrics Publisher | la DCR del latido (lo asigna la plataforma, G-7; FLW-006) |
| investigate, publish | Cognitive Services User | la cuenta de Foundry, cuando exista (G-6) |
| migrate | administrador Entra de PostgreSQL | el servidor (FLW-035) |
| daily | Cost Management Reader | el RG (G-17; lo asigna la plataforma: no está en la lista de G-2) |

El pipeline solo puede asignar Key Vault Crypto User, Key Vault Secrets User, Monitoring Metrics
Publisher y Cognitive Services User, solo a los `principalId` de api, cloudflared, ingest,
investigate, publish y daily, y solo a principales de tipo `ServicePrincipal` (ADR-0014,
THR-010). No puede dárselos a sí mismo ni a otra identidad del tenant.

## Origen sin IP pública (ADR-0004, CTL-008)

El entorno es interno y ninguna app tiene ingress externo. El tráfico de Internet llega por
CMP-011 y el Tunnel (FLW-005): `cloudflared` llama a la API por su nombre interno dentro del
entorno.
