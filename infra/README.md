# infra

Infraestructura como código del núcleo en Azure (PLAN §2). Bicep, por módulos. Vista:
`docs/architecture/views/deployment.md`.

| Fichero | Qué | Quién lo despliega |
|---|---|---|
| `main.bicep` + `modules/` | Red, Key Vault con la clave de firma, PostgreSQL, entorno ACA, API, cloudflared, jobs, identidades, Log Analytics y App Insights | `.github/workflows/deploy.yml` (manual, entorno `prod`, OIDC) |
| `main.bicepparam` | Parámetros de ejemplo con valores ficticios; los reales llegan por variables de entorno desde los secrets del entorno `prod` | — |
| `platform/` | Requisitos de plataforma: RG, identidades de los componentes, identidad OIDC del pipeline con RBAC con condición limitada a esas identidades, latido (DCR, tabla y rol de los jobs) y presupuesto | El programa de la plataforma, con aprobación de Juan (gate) |
| `scripts/az-quiet.sh` | Ejecuta `az` en `deploy.yml` y, si falla, solo enseña el código de error (los logs de Actions serán públicos) | — |

## Probar en local

El producto entero en un equipo, con datos reales y sin nada de Azure ni de Cloudflare
(`compose.yaml`, `infra/compose/Dockerfile`):

```bash
docker compose up -d
docker compose ps                                   # migrate: Exited (0); el resto, Up
docker compose logs -f worker                       # una línea JSON por ejecución de fuente
curl -s http://127.0.0.1:8080/v1/feed/all/changes   # índice del feed, con el estado de cada fuente
```

| Servicio | Qué hace | Punto de entrada |
|---|---|---|
| `db` | PostgreSQL 17, sin puerto publicado ni contraseña (solo la red de compose) | — |
| `migrate` | Migraciones de Alembic y termina | `python -m vs.model.migrate upgrade head` |
| `worker` | Cada 5 min `ingest` y `publish`; cada hora `daily`. Cada job en su proceso | `python -m vs.jobs.loop` |
| `api` | API pública y portal (`web/dist`) en el mismo origen, en `127.0.0.1:8080` | `python -m vs.api.serve` |

Los puntos de entrada son los mismos que usa `main.bicep` (`entrypoints`):

| Módulo | Qué hace | Salida |
|---|---|---|
| `vs.api.serve` | uvicorn con `create_app`; lee el feed de `feed_record`/`feed_change` y las métricas de `metric_daily` | — |
| `vs.jobs.ingest` | Una ejecución de cada conector de ingesta de la instancia (cvelistV5 primero), `source_run`, reglas y alertas | 0; 1 si una ejecución no se pudo guardar; 2 configuración |
| `vs.jobs.publish` | Feed completo y de alertas, firmados con `LocalDevSigner`; escribe en `VS_FEED_DIR` (R2 en la F1b) | 0; 1; 2 |
| `vs.jobs.daily` | `metric_daily` de ayer y hoy (o de las fechas dadas) | 0; 1; 2 |
| `vs.jobs.investigate` | Apagado salvo `VS_AGENT_ENABLED=1`; encendido, sale con 3: el agente real llega en la F1b | 0; 3 |

Configuración por entorno: tabla en `src/vs/jobs/settings.py`. Una fuente caída no hace fallar el
job: queda en UNKNOWN en `source_run` y en el índice del feed (fail-closed).

Notas:

- **Carga inicial.** La primera ejecución de cada fuente no alerta (ADR-0012). Un hecho visto en
  la carga inicial de su fuente nunca alerta después, aunque su CVE llegue más tarde.
- **Primer ciclo lento.** cvelistV5 lee las últimas 24 h registro a registro (miles de peticiones);
  los ciclos siguientes solo leen lo nuevo.
- **GitHub.** GHSA y nomi-sec usan la API de GitHub. Sin `VS_GITHUB_TOKEN` (opcional, del entorno
  de quien lanza compose) van con el límite anónimo y pueden salir en UNKNOWN.
- **Proxy TLS.** Si la red reinspecciona TLS, las fuentes afectadas salen en UNKNOWN con
  `CERTIFICATE_VERIFY_FAILED`. `compose.ca.yaml` monta el almacén de CA del anfitrión
  (`VS_CA_BUNDLE`, por defecto `/etc/ssl/certs/ca-certificates.crt`) y lo usa como
  `SSL_CERT_FILE`: `docker compose -f compose.yaml -f compose.ca.yaml up -d`. Nunca se desactiva la
  verificación.
- **Reintentos.** Un 502/503/504 se reintenta dos veces (1 s y 4 s); un 403 o 429 no.
- **Firma.** Clave de desarrollo generada en el volumen `data`. Nunca se usa fuera de local.
- **Borrar todo:** `docker compose down -v`.

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

- ~~Puntos de entrada de la API y de los jobs (`entrypoints` en `main.bicep`).~~ Hechos en T13
  (ver «Probar en local»). Falta en Azure: `KeyVaultSigner`, escritura del feed en R2 y el agente.
- Conexión a PostgreSQL con token de Entra ID y roles de base de datos de cada identidad.
- Latido por la Logs Ingestion API y trazas OTel con Entra ID.
