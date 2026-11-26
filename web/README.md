# Portal (CMP-001)

SPA de Vite + React + TypeScript sobre shadcn/ui y sus gráficas (ADR-0005, ADR-0023). Es un
consumidor más de la API pública (D10): solo `GET`, sin credenciales.

## Pantallas

| Ruta | Pantalla | Datos |
|---|---|---|
| `/` | Hoy | `/v1/feed/alerts/changes` y `/v1/feed/alerts/latest.json` |
| `/alertas/:id` | Detalle de alerta | `/v1/vulns/{id}.json` |
| `/metricas` | Métricas | `/v1/metrics/daily.json` (nombres en `src/api/metrics.ts`) |
| `/fuentes` | Fuentes (detrás de Access) | datos de ejemplo (`src/fixtures/restricted.ts`) |
| `/admin` | Administración (detrás de Access) | datos de ejemplo |

## Configuración

Solo variables `VITE_*` (ADR-0016); ver `env.example`. Colores, temas y tipografía: solo en
`src/theme/tokens.css`.

## Comandos

```bash
npm ci
npm run lint        # eslint + tsc
npm run build
npm test            # Vitest + Testing Library
npx playwright install chromium   # una vez (en Linux puede pedir --with-deps)
npm run test:smoke  # build + API de T6 con fixtures (uv run) + 5 pantallas + axe
```

La prueba de humo arranca `uv run python -m tests.portal_fixture` desde la raíz del repo: sirve en
`127.0.0.1` la API con fixtures y el build en el mismo origen.
