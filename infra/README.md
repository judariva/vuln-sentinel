# infra

Infraestructura como código del núcleo en Azure (PLAN §2). Bicep, por módulos. Vista:
`docs/architecture/views/deployment.md`.

| Fichero | Qué | Quién lo despliega |
|---|---|---|
| `main.bicep` + `modules/` | Red, Key Vault con la clave de firma, PostgreSQL, entorno ACA, API, cloudflared, jobs, identidades, Log Analytics y App Insights | `.github/workflows/deploy.yml` (manual, entorno `prod`, OIDC) |
| `main.bicepparam` | Parámetros de ejemplo con valores ficticios; los reales llegan por variables de entorno desde los secrets del entorno `prod` | — |
| `platform/` | Requisitos de plataforma: RG, identidad OIDC del pipeline con RBAC con condición, latido (DCR y tabla) y presupuesto | El programa de la plataforma, con aprobación de Juan (gate) |

## Validar en local

Solo compilar y pasar el lint. Ninguna sesión despliega.

```bash
az bicep build --file infra/main.bicep --stdout > /dev/null
az bicep lint --file infra/main.bicep
az bicep lint --file infra/main.bicepparam
az bicep build --file infra/platform/platform.bicep --stdout > /dev/null
az bicep lint --file infra/platform/platform.bicep
az bicep lint --file infra/platform/platform.bicepparam
uv run --no-project --with actionlint-py==1.7.12.25 actionlint
```

La CI hace lo mismo en el job `infra`.

## Orden del primer despliegue

1. Plataforma: `platform/platform.bicep` sin `publisherPrincipalIds`.
2. `images.yml` y después `deploy.yml` con el digest, primero con `what_if_only`, con los nombres
   de secretos vacíos: se crea el Key Vault, pero no cloudflared ni las lecturas de secretos.
3. Secretos en el Key Vault (token del Tunnel y los opcionales), con caducidad (G-5). El vault no
   tiene acceso público: se crean por ARM (`Microsoft.KeyVault/vaults/secrets` con parámetro
   seguro), no con `az keyvault secret set`.
4. `deploy.yml` otra vez, con `VS_KV_SECRET_TUNNEL` y los demás nombres: entra cloudflared.
5. Job `migrate` (manual).
6. Plataforma otra vez, con los `principalIds` que da `main.bicep`, para el rol en la DCR.

## Pendiente (F1a)

- Puntos de entrada de la API y de los jobs (`entrypoints` en `main.bicep`).
- Conexión a PostgreSQL con token de Entra ID y roles de base de datos de cada identidad.
- Latido por la Logs Ingestion API y trazas OTel con Entra ID.
