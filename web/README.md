# Portal (CMP-001)

SPA de Vite + React + TypeScript sobre shadcn/ui y sus gráficas (ADR-0005, ADR-0023). Es un
consumidor más de la API pública (D10): solo `GET`, sin credenciales.

## Pantallas

| Ruta | Pantalla | Datos |
|---|---|---|
| `/` | Hoy | `/v1/feed/alerts/changes`, `/v1/feed/alerts/latest.json` y, para el embudo, `/v1/feed/all/changes` |
| `/alertas/:id` | Detalle de alerta | `/v1/vulns/{id}.json` |
| `/metricas` | Métricas | `/v1/metrics/daily.json` (nombres en `src/api/metrics.ts`) |
| `/fuentes` | Fuentes (detrás de Access) | datos de ejemplo (`src/fixtures/restricted.ts`) |
| `/gestion` | Administración (detrás de Access) | datos de ejemplo |

Movimiento y 3D (ADR-0024): Motion, Magic UI (`src/components/magicui/`) y la escena del embudo
(`src/components/funnel/`), que se carga aparte y sola, después de `load` y con el navegador libre
(T8c). Con `prefers-reduced-motion`, sin WebGL o con WebGL por software (sin GPU: SwiftShader,
llvmpipe…), SVG estático con las mismas cifras (T8d). La escena se monta por fases y va a 30 fps; en
pantallas pequeñas o con ≤ 4 núcleos dibuja menos partículas. `?escena=forzar` la carga sin GPU: es
un parámetro de prueba (Playwright, Lighthouse), sin enlace en el portal.

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
npm run budget      # tras el build: JS inicial <= 250 KB y bloque 3D <= 400 KB (gzip)
npm run perf        # tras el build: Lighthouse (móvil y escritorio, mediana de 3, umbrales de ADR-0024)
                    # en las 5 pantallas; en local solo orienta, el juez es el job `lighthouse` de CI.
                    # Añade Hoy móvil con la escena forzada, solo como dato (sin umbral)
npm run shots       # capturas con el fixture de volumen (--volume 240), en ../local/tmp/shots
```

La prueba de humo arranca `uv run python -m tests.portal_fixture` desde la raíz del repo: sirve en
`127.0.0.1` la API con fixtures y el build en el mismo origen.
