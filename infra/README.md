# infra

Infraestructura como código del núcleo en Azure (PLAN §2). Bicep, por módulos. Vista:
`docs/architecture/views/deployment.md`.

| Fichero | Qué | Quién lo despliega |
|---|---|---|
| `main.bicep` + `modules/` | Red, Key Vault con la clave de firma, PostgreSQL, entorno ACA, API, cloudflared, jobs, identidades, Log Analytics y App Insights | `.github/workflows/deploy.yml` (manual, entorno `prod`, OIDC) |
| `main.bicepparam` | Parámetros de ejemplo con valores ficticios; los reales llegan por variables de entorno desde los secrets del entorno `prod` | — |
| `platform/` | Requisitos de plataforma: RG, identidades de los componentes, identidad OIDC del pipeline con RBAC con condición limitada a esas identidades, latido (DCR, tabla y rol de los jobs) y presupuesto | El programa de la plataforma, con aprobación de Juan (gate) |
| `scripts/az-quiet.sh` | Ejecuta `az` en `deploy.yml` y, si falla, solo enseña el código de error (los logs de Actions serán públicos) | — |

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

## Gate de GitHub: lista de comprobación (la hace Juan en la web)

No es código: son ajustes del repo. Sin ellos, el pipeline no tiene las garantías que dan por
hechas ADR-0014 y CTL-020. Se marcan antes del primer `deploy.yml`.

- [ ] **Entorno `prod`** (Settings → Environments) con **Juan como revisor obligatorio** («Required
      reviewers»). Sin «Allow administrators to bypass configured protection rules».
- [ ] **Ramas de despliegue del entorno `prod` = solo `main`** («Deployment branches and tags» →
      «Selected branches and tags» → `main`). La credencial federada confía en
      `repo:<repo>:environment:prod`; esta regla es la que ata ese entorno a `main`.
- [ ] Los secrets de `deploy.yml` (lista en su cabecera) **en el entorno `prod`**, no a nivel de
      repo.
- [ ] **Protección de `main`**: PR obligatorio, CI en verde obligatoria (jobs `test`, `infra`, `web`
      y `lighthouse`), sin push directo y **sin bypass de administradores** («Do not allow
      bypassing the above settings»). Mientras el repo sea privado sin plan de pago, solo cubre el
      hook `pre-push` local (regla 9 de `CLAUDE.md`); al hacerlo público se aplica aquí.
- [ ] **Paquete de GHCR** con la **visibilidad del repo** (privado mientras el repo lo sea,
      público después) y con acceso solo para este repo («Manage Actions access»). Si sigue
      privado al desplegar, ACA necesita credenciales de registro (pregunta abierta de T9).
- [ ] Dependabot activado (lee `.github/dependabot.yml`).

## Orden del primer despliegue

1. Plataforma: `platform/platform.bicep`. Crea también las identidades de los componentes y les
   da el rol en la DCR del latido; la condición del pipeline lleva sus `principalId` (ADR-0014).
2. `images.yml` (build, SBOM y procedencia) y después `deploy.yml` con el digest, primero con
   `what_if_only`, con los nombres de secretos vacíos: se crea el Key Vault, pero no cloudflared
   ni las lecturas de secretos. `deploy.yml` para si la imagen no tiene la procedencia de
   `images.yml`.
3. Secretos en el Key Vault (token del Tunnel y los opcionales), con caducidad (G-5). El vault no
   tiene acceso público: se crean por ARM (`Microsoft.KeyVault/vaults/secrets` con parámetro
   seguro), no con `az keyvault secret set`.
4. `deploy.yml` otra vez, con `VS_KV_SECRET_TUNNEL` y los demás nombres: entra cloudflared.
5. Job `migrate` (manual).

Si la plataforma cambia el prefijo o los nombres de las identidades, `main.bicep` los recibe en
`identityNames` (por defecto `<prefijo>-id-<componente>`).

## Comprobaciones tras el primer despliegue

- **Compresión del portal en Workers static assets** (ADR-0024, decisión de Juan en T8c). Que el
  borde comprima los assets está SIN VERIFICAR en la documentación de static assets. Se comprueba
  con el host real del portal (no se escribe aquí):

  ```bash
  curl -sI -H 'Accept-Encoding: br, gzip' https://<host-del-portal>/assets/<bloque>.js
  ```

  Tiene que volver `content-encoding: br` o `gzip` en el HTML, el JS, el CSS y el JSON de la API.
  Si no vuelve, los presupuestos en gzip de `npm run budget` y la medida de Lighthouse de la CI no
  reflejan lo que descarga quien visita el portal: se abre una pregunta para Juan antes de seguir.

## Pendiente (F1a)

- Puntos de entrada de la API y de los jobs (`entrypoints` en `main.bicep`).
- Conexión a PostgreSQL con token de Entra ID y roles de base de datos de cada identidad.
- Latido por la Logs Ingestion API y trazas OTel con Entra ID.
