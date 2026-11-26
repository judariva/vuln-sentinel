# vuln-sentinel

Monitor 24/7 de vulnerabilidades **nuevas y peligrosas**. Clasifica por peligro, no por CVSS:

- **A, inmediato**: explotación activa confirmada.
- **B, urgente**: exploit público funcional, con impacto mínimo, en un producto expuesto a
  Internet de uso masivo.
- **C, vigilar**: RCE sin autenticación en un producto masivo, todavía sin exploit.

Publica un feed **OSV 1.9 extendido y firmado** (JWS detached) que cualquier herramienta puede
cruzar con su inventario sin IA. El monitor no sabe quién lo consume.

Estado: **F0 (arranque)**. Ver [PLAN.md](PLAN.md) y [STATE.md](STATE.md).

## Probar en local en 5 minutos

Con Docker y Docker Compose, sin cuentas ni secretos:

```bash
docker compose up -d                 # PostgreSQL, migraciones, jobs y API + portal
docker compose logs -f worker        # ingest → publish cada 5 min; daily cada hora
```

- Portal: <http://127.0.0.1:8080>. API: `http://127.0.0.1:8080/v1/feed/all/changes`.
- Datos reales de las fuentes abiertas de `config/instance.public.yaml`. La primera ejecución de
  cada fuente es su **carga inicial**: no alerta. Desde el segundo ciclo solo alerta lo nuevo.
- El primer ciclo tarda más (cvelistV5 lee las últimas 24 h, registro a registro).
- Opcional: `VS_GITHUB_TOKEN=<token sin permisos> docker compose up -d` sube el límite de GitHub
  para GHSA y nomi-sec. Sin él, si se agota el límite anónimo, esas fuentes salen en UNKNOWN.
- Parar: `docker compose down` (conserva los datos); `docker compose down -v` los borra.

Detalle en [infra/README.md](infra/README.md#probar-en-local).

## Desarrollo

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run pytest
```

Las pruebas con PostgreSQL (`-m db`, entre ellas la de humo de los jobs, `tests/test_jobs.py`) se
saltan sin `VS_TEST_DATABASE_URL`:

```bash
docker run -d --rm --name vs-pg-test -e POSTGRES_PASSWORD=test -p 127.0.0.1:55432:5432 postgres:17
VS_TEST_DATABASE_URL=postgresql://postgres:test@127.0.0.1:55432/postgres uv run pytest
docker stop vs-pg-test
```

## Licencia

Código bajo [Apache-2.0](LICENSE). Las atribuciones de los datos de terceros están en [NOTICE](NOTICE).
