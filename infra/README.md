# infra

Infraestructura como código del núcleo en Azure (PLAN §2). Terraform, modelo híbrido (ADR-0025):
la plataforma pone el landing zone y despliega; este repo pone el módulo del producto. Vista:
`docs/architecture/views/deployment.md`.

| Ruta | Qué | Quién lo despliega |
|---|---|---|
| `terraform/modules/vuln-sentinel/` | Módulo del producto: entorno ACA, API, jobs, cloudflared opcional, PostgreSQL con endpoint privado y diagnósticos. Salida `required_platform_grants` con los roles que concede el vending a las UAMI `runtime` y `publish` | La factoría de la plataforma, fijado por versión, con aprobación de Juan |
| `terraform/examples/golden-lab/` | Cómo se instancia en lab (LAB), con valores ficticios, versión exacta y lock | Nadie: solo se valida |
| `terraform/.tflint.hcl` | tflint con versiones fijadas | — |
| `bicep-legacy/` | Bicep de T9 y T9b y el `deploy.yml` retirado. Referencia; no se despliega | — |
| `compose/`, `local/` | Prueba en local | — |

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

Los puntos de entrada son los mismos que usa el módulo Terraform (`args` de cada app y job):

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

Solo validar. Ninguna sesión despliega ni hace `plan` (sin credenciales ni backend). Comandos en
`terraform/modules/vuln-sentinel/README.md`. La CI lo hace en el job `terraform` (fmt, validate,
tflint, Checkov) y `tests/test_terraform.py` comprueba los controles CORE que Checkov no cubre.
`actionlint` va en el job `infra`.

## Gate de GitHub: lista de comprobación (la hace Juan en la web)

No es código: son ajustes del repo. Desde ADR-0025 este repo no despliega: ya no hacen falta el
entorno `prod` ni sus secrets (eran de `deploy.yml`).

- [ ] **Protección de `main`**: PR obligatorio, CI en verde obligatoria (jobs `test`, `infra`,
      `terraform`, `web` y `lighthouse`), sin push directo y **sin bypass de administradores** («Do not allow
      bypassing the above settings»). Mientras el repo sea privado sin plan de pago, solo cubre el
      hook `pre-push` local (regla 9 de `CLAUDE.md`); al hacerlo público se aplica aquí.
- [ ] **Paquete de GHCR** con la **visibilidad del repo** (privado mientras el repo lo sea,
      público después) y con acceso solo para este repo («Manage Actions access»). Si sigue
      privado al desplegar, ACA necesita credenciales de registro. Con `image_registry = acr`, el
      valor por defecto desde T16b (D-4), no aplica: GHCR queda para terceros.
- [ ] Dependabot activado (lee `.github/dependabot.yml`).

## Orden del primer despliegue (lo ejecuta la plataforma)

1. Vending: landing zone (RG, las dos UAMI `runtime` y `publish`, Key Vault privado, presupuesto,
   guardarraíles), la **clave de firma** EC P-256 no exportable en ese vault (P-4), la subred de
   ACA, y la DCR y tabla del latido (esquema de referencia en
   `bicep-legacy/platform/modules/heartbeat.bicep`). La subred de endpoints compartida y la zona
   `privatelink.postgres.database.azure.com` ya son de la plataforma.
2. `images.yml` (build, SBOM y procedencia) y réplica al ACR de la imagen del producto y de
   cloudflared (D-4). El workflow de la plataforma verifica la procedencia antes de aplicar
   (CTL-026, requisito para golden en ADR-0025).
3. Vending: concede los roles de `required_platform_grants` (todos los alcances se conocen antes
   de aplicar: ACR, secretos, clave, DCR) y pone los secretos con caducidad (G-5).
4. Apply del módulo.
5. Job `migrate` (manual).

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

- ~~Puntos de entrada de la API y de los jobs.~~ Hechos en T13
  (ver «Probar en local»). Falta en Azure: `KeyVaultSigner`, escritura del feed en R2 y el agente.
- Conexión a PostgreSQL con token de Entra ID y roles de base de datos de cada identidad.
- Latido por la Logs Ingestion API y trazas OTel con Entra ID.
