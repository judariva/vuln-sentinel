---
adr: "0023"
titulo: Portal con Vite, React, Tailwind y shadcn/ui
estado: aceptado
fecha: 2026-11-26
afecta: [CMP-001, CMP-002, FLW-030, THR-016, CTL-018]
sustituye: null
---

## Contexto

ADR-0005 fija el front como SPA de React construida con Vite y servida con Workers static assets.
Falta decidir sobre qué base se construye. El portal es un consumidor más de la API pública (D10) y
no debe crecer con primitivas propias (botones, tablas, gráficas) que ya existen hechas. Todo el
repo es Apache-2.0 (ADR-0011): cada dependencia debe tener una licencia compatible.

## Decisión

Decisión de Juan (T8a):

- **Vite + React + TypeScript**, con **Tailwind** para el estilo.
- **shadcn/ui** (sobre Radix) para los componentes: se copian a `web/src/components/ui/` con su CLI
  y no se escriben primitivas propias si existen en shadcn.
- **Gráficas de shadcn** (sobre Recharts).
- Sistema visual en un solo fichero, `web/src/theme/tokens.css`: colores de A, B y C iguales en
  todo el portal, tema oscuro por defecto y claro, una sola familia tipográfica (la del sistema, sin
  descargas de terceros). `web/src/theme/tokens.ts` solo nombra las variables.
- Hosts, marca y URL base solo por `VITE_*` (ADR-0016): `VITE_API_BASE_URL` y `VITE_BRAND_NAME`.
- **Versiones exactas** en `web/package.json` (sin `^` ni `~`) y `package-lock.json` en el repo.
- Pruebas: Vitest + Testing Library (componentes) y Playwright + axe (humo de las 5 pantallas contra
  la API de T6 con fixtures, sin violaciones serious/critical).

## Versiones y licencias

Comprobadas el 2026-11-26 en el registro npm (`npm view <paquete> version license`; `version` es
la etiqueta `latest`). URL de cada paquete: `https://www.npmjs.com/package/<paquete>`.

| Paquete | Versión fijada | Licencia | Uso |
|---|---|---|---|
| react, react-dom, react-is | 19.3.1 | MIT | ejecución |
| react-router | 8.5.3 | MIT | ejecución |
| recharts | 3.11.1 | MIT | ejecución (gráficas de shadcn) |
| radix-ui | 1.8.1 | MIT | ejecución (base de shadcn/ui) |
| class-variance-authority | 0.7.1 | Apache-2.0 | ejecución (shadcn/ui) |
| clsx | 2.1.1 | MIT | ejecución (shadcn/ui) |
| tailwind-merge | 3.7.1 | MIT | ejecución (shadcn/ui) |
| lucide-react | 1.81.0 | ISC | ejecución (iconos de shadcn/ui) |
| shadcn (CLI) | 4.23.1 | MIT | solo para copiar componentes (`npx shadcn@4.23.1`); no es dependencia |
| vite | 8.3.8 | MIT | build |
| @vitejs/plugin-react | 6.3.0 | MIT | build |
| typescript | 6.0.3 | Apache-2.0 | build |
| tailwindcss, @tailwindcss/vite | 4.3.5 | MIT | build |
| tw-animate-css | 1.4.0 | MIT | build |
| vitest | 5.1.2 | MIT | tests |
| @testing-library/react | 16.3.3 | MIT | tests |
| @testing-library/dom | 10.4.2 | MIT | tests |
| @testing-library/jest-dom | 8.0.0 | MIT | tests |
| @testing-library/user-event | 14.6.13 | MIT | tests |
| jsdom | 31.0.1 | MIT | tests |
| @playwright/test | 1.65.1 | Apache-2.0 | tests |
| @axe-core/playwright, axe-core | 4.14.1 | **MPL-2.0** | tests (ver abajo) |
| eslint | 10.15.0 | MIT | lint |
| @eslint/js | 10.0.1 | MIT | lint |
| typescript-eslint | 8.74.0 | MIT | lint |
| eslint-plugin-react-hooks | 7.1.1 | MIT | lint |
| globals | 17.14.0 | MIT | lint |
| @types/react 19.3.3, @types/react-dom 19.3.0, @types/node 24.19.4 | — | MIT | tipos |

**TypeScript 6 y no 7.** La etiqueta `latest` es 7.0.2, pero `typescript-eslint` 8.74.0 declara
`typescript: '>=4.8.4 <6.1.0'` como dependencia par. Se fija 6.0.3, la última 6.x.

**axe-core (MPL-2.0).** Es copyleft débil por fichero. Solo se usa en los tests: no entra en el
build ni se distribuye con el portal, y no se modifica. La política de licencias de la ASF la pone en
la categoría B (compatible con Apache-2.0 en forma binaria):
https://www.apache.org/legal/resolved.html (leída el 2026-11-26): «Mozilla Public Licenses: MPL 1.0,
MPL 1.1, and MPL 2.0», en la lista que empieza «You may include software under the following
licenses in binary form within an Apache product if you label the inclusion appropriately (see
above):». La misma página no habla de dependencias que solo se usan en los tests.

**Node 24.18.0** en local y en la CI (`react-router` 8.5.3 exige `node >=22.22.0`).

## Alternativas descartadas

- Primitivas propias o CSS a mano: más código que mantener y más superficie para errores de
  accesibilidad; shadcn/ui da componentes accesibles (Radix) que quedan en el repo y se pueden leer.
- Otra librería de componentes empaquetada (no copiada): el código no queda en el repo y el tema
  depende de su sistema; shadcn/ui usa variables CSS que encajan con un único fichero de tokens.
- Fuente tipográfica descargada de un CDN: añade un tercero en cada visita. Se usa la del sistema.

## Consecuencias

- Los componentes de `web/src/components/ui/` son código del repo (copiado por la CLI de shadcn):
  sus actualizaciones son un cambio revisable, no un `npm update`.
- La CLI de shadcn 4.23.1 no resolvió el alias `@/lib/utils` y escribió `import { cn } from "cn"`
  y una dependencia `cn` que nadie pidió; se corrigió a mano y se quitó la dependencia. Al añadir
  componentes hay que revisar lo que toca la CLI en `package.json`.
- La API y el portal van en orígenes distintos en producción (ADR-0016): la API necesitará CORS para
  el host del portal, o servirse bajo el mismo host. La API de T6 no envía CORS (pregunta abierta).
- Fuentes y Administración muestran datos de ejemplo, no de la API (`/admin/*` es un esqueleto que
  responde 501). Quedan marcadas como «detrás de Access».
- Control nuevo: CTL-018 frente a THR-016 (enlaces del feed que no son https nunca llegan a un `href`).

## Evidencia

- Registro npm, `npm view <paquete> version license` y `peerDependencies`, 2026-11-26.
- https://www.apache.org/legal/resolved.html, 2026-11-26 (citas arriba).
- Decisión de stack: Juan, tarea T8a de la noche del 2026-11-25.
