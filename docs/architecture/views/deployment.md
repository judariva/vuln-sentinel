# Vista de despliegue

Qué se despliega, dónde y quién lo escribe. Solo IDs de `architecture.yaml`; ningún nombre,
rango ni ID real (regla 8). Código: `infra/terraform/` (módulo y ejemplo) y `.github/workflows/`.
Modelo híbrido (ADR-0025): la plataforma pone el landing zone y despliega; este repo pone el
módulo del producto.

## Quién escribe

| Paso | Quién | Qué |
|---|---|---|
| Landing zone | CMP-039, vending de la plataforma, con aprobación de Juan | RG, las dos identidades (CMP-026), Key Vault privado con la clave de firma, red (CMP-025), presupuesto, guardarraíles y los roles de `required_platform_grants` (FLW-045, CTL-019). DCR y tabla del latido en el workspace de Sentinel (G-7, CMP-012) |
| Imagen | CMP-028 (`images.yml`, al fusionar en `main`) | Imagen única por digest (FLW-031), con SBOM y procedencia firmados (CTL-026), replicada al ACR de la plataforma junto con la de cloudflared. La factoría verifica la procedencia antes de aplicar |
| Producto | CMP-039, con el módulo CMP-038 fijado por versión (FLW-044) | Entorno de ACA, API, jobs, PostgreSQL con su endpoint privado y diagnósticos en el RG del landing zone (CTL-032). Este repo no entra en Azure (CTL-031) |
| Sesión local y CI | Nadie escribe | `terraform fmt`, `validate`, `tflint` y Checkov, sin credenciales ni backend |

## Qué hay en el RG del producto

```
CMP-025 red de la plataforma ─┬─ subred aca (delegada) ── entorno ACA, solo Consumption, interno
                              │                            ├─ CMP-002 api         (ingress interno, 0–1, probes)
                              │                            ├─ CMP-010 cloudflared (opcional; 1 réplica, sin ingress)
                              │                            ├─ CMP-003 ingest      cron */5
                              │                            ├─ CMP-004 investigate manual mientras esté apagado
                              │                            ├─ CMP-005 publish     cron */10
                              │                            ├─ CMP-006 daily       cron diario (UTC)
                              │                            └─ CMP-027 migrate     manual
                              └─ subred de endpoints (compartida) ── endpoint privado ── CMP-007 PostgreSQL B1ms,
                                                                    sin acceso público, solo Entra; registro A en
                                                                    la zona privatelink de la plataforma
CMP-008 Key Vault del landing zone (RBAC, privado) ── clave de firma creada por el vending
CMP-026 identidades runtime y publish (las crea el vending; el módulo solo las referencia)
```

Fuera del RG: el workspace de diagnóstico de la plataforma (allLogs del entorno y de PostgreSQL;
CMP-030 se retiró), CMP-012 (workspace de Sentinel, DCR y tabla del latido), CMP-014 (App
Insights, opcional), CMP-009 (Foundry, pendiente de G-6), CMP-011 y CMP-016 (Cloudflare, G-10,
G-11, G-15).

## Roles (CTL-019): salida `required_platform_grants`

El módulo no crea ninguna asignación. Las lista por identidad, rol y alcance, y las concede el
vending. `runtime` la usan api, cloudflared, ingest, investigate, daily y migrate; `publish`, solo
el job publish.

| Identidad | Rol | Alcance (componentes que lo usan) |
|---|---|---|
| publish | Key Vault Crypto User | la clave de firma (FLW-004) |
| runtime | Key Vault Secrets User | el secreto del token del Tunnel (cloudflared, FLW-034), si está activo |
| runtime | Key Vault Secrets User | el secreto del token de GitHub (ingest, investigate), si existe |
| publish | Key Vault Secrets User | el secreto del token de R2 (G-15), si existe |
| runtime, publish | Monitoring Metrics Publisher | App Insights (FLW-036), si existe |
| runtime, publish | Monitoring Metrics Publisher | la DCR del latido (G-7; FLW-006) |
| runtime, publish | Cognitive Services User | la cuenta de Foundry, cuando exista (G-6) |
| runtime | Cost Management Reader | el RG (daily, G-17) |
| runtime, publish | AcrPull | el ACR (`image_registry = acr`, por defecto) |
| runtime (o `postgres_entra_admin`) | administrador Entra de PostgreSQL | el servidor (FLW-035; lo crea el módulo, no es un rol de Azure) |

## Origen sin IP pública (ADR-0004, CTL-008)

El entorno es interno y ninguna app tiene ingress externo. El tráfico de Internet llega por
CMP-011 y el Tunnel (FLW-005): el conector (el de la plataforma en lab, o `cloudflared` del
módulo) llama a la API por su nombre interno.
