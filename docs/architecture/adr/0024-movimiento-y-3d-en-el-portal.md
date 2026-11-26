---
adr: "0024"
titulo: Movimiento y escena 3D en el portal, sin tocar la fiabilidad de los datos
estado: aceptado
fecha: 2026-11-26
afecta: [CMP-001, THR-021, CTL-025]
sustituye: null
---

## Contexto

T8b da vida al portal de ADR-0023: transiciones, contadores de KPI, haces entre fuentes y núcleo,
rejilla bento y una escena 3D en Hoy («el embudo vivo»). La condición es que nada de eso cambie una
cifra ni retrase los datos: cada número sale de la API (D10), la escena se carga aparte y, con
`prefers-reduced-motion` o sin WebGL, hay una versión estática.

## Decisión

Decisión de Juan (T8b): **Motion**, **Magic UI** (solo contadores, haces y bento) y
**react-three-fiber + drei** para la escena. Lo que se ha implementado:

- **Motion** con `LazyMotion` + `domAnimation` y componentes `m` (`strict`), dentro de
  `MotionConfig reducedMotion="user"`. Transición entre pantallas (solo desplazamiento: sin opacidad,
  para que axe no mida contraste a medio aparecer) y latido de la insignia cuando un nivel cambia en un
  refresco de Hoy (cada 5 min). Las entradas de las listas, con CSS (`motion-safe:`).
- **Magic UI** copiado y adaptado en `web/src/components/magicui/` (no hay paquete npm): `number-ticker`,
  `animated-beam` y `bento-grid`, leídos del registro `https://magicui.design/r/<componente>.json` el
  2026-11-26. Cambios: colores de `tokens.css`, formato `es-ES`, valor real del contador siempre en el
  DOM (`sr-only` y `data-value`), haz cortado y discontinuo para una fuente en UNKNOWN, sin
  `@radix-ui/react-icons`. Licencia MIT conservada en `LICENSE-magicui.md`.
- **Escena 3D** (`web/src/components/funnel/FunnelScene.tsx`): cada CVE con cambios hoy en el feed
  completo es una partícula (instancias de three.js) que baja en espiral; las que acaban en A, B o C
  toman el color de su nivel (las variables de `tokens.css`, resueltas a sRGB en un canvas 2D) y caen
  sobre la columna de su tarjeta. Al pasar el ratón, la CVE (drei `Html`). Posiciones por hash del id,
  no por azar. Como mucho 1500 partículas; las alertas siempre se dibujan y el texto dice cuántas de
  cuántas.
- **Robustez.** La escena es otro bloque (`lazy`). **Revisado en T8c (decisión de Juan): viva al
  llegar, sin esperar a que se interactúe**, pero nunca antes que los datos: `load` del documento →
  dos fotogramas → navegador libre (`requestIdleCallback`, o `setTimeout` sin él) → se descarga y
  evalúa el bloque → en otro momento libre se monta el `Canvas` (el trabajo, partido en dos tareas).
  En T8b se pedía tras la primera interacción. Mientras llega, si falla (error de WebGL o bloque que
  no llega) y con `prefers-reduced-motion` o sin WebGL se ve `FunnelStatic` (SVG) con las mismas
  cifras. El embudo tiene su propia petición (`/v1/feed/all/changes`) y se monta después de pintar
  las alertas: si falla, solo falla su tarjeta. Un e2e comprueba que el bloque se pide sin
  interacción y después de `loadEventEnd` y de la última respuesta de la API.
- **Dirección de arte (T8c).** Todas las CVE del día entran por arriba, escalonadas, y bajan en
  espiral; las que no tienen nivel se apagan y se posan en el fondo como polvo; las A, B y C se
  encienden con el color de su nivel, **con brillo** y caen sobre su plataforma. El brillo es un
  **sprite aditivo** (máscara radial generada en un canvas, `Points` con `AdditiveBlending` en oscuro
  y mezcla normal en claro), no el bloom de `@react-three/postprocessing`: sin dependencia nueva,
  sin coste de presupuesto y sin el problema del bloom con un lienzo transparente (trata mal el alfa
  y en el tema claro no se ve). El embudo tiene superficie (malla de revolución translúcida, anillos
  y meridianos), niebla con el color de la tarjeta y un vaivén lento de cámara (±0,2 rad, para que
  las plataformas sigan sobre su etiqueta). Las etiquetas de los destinos (`A · n`) salen de la
  escena a HTML (`FunnelLabels`), bajo el lienzo, compartidas con el SVG; en la escena solo queda la
  etiqueta de la CVE bajo el ratón.
- **Hoy en bento de 4 columnas (T8c):** embudo en 3, tarjeta «El día en cifras» al lado (CVE con
  cambios, cuántas acaban en alerta, cuántas sin nivel, cambios del feed de alertas y una barra de
  reparto por nivel con su leyenda en texto), A, B y C debajo de su plataforma y los cambios del día a
  lo ancho.
- **Rendimiento del resto del portal** (para Lighthouse): todas las pantallas salvo Hoy en bloques
  aparte; en Métricas, Recharts en su propio bloque, cada gráfica se monta al entrar en pantalla y con
  el navegador libre, y sin animación de Recharts (anima volviendo a pintar React en cada fotograma).
  Los datos de la API se pintan en una transición de React (`startTransition`).
- **Presupuestos en CI** (`web/scripts/check-budgets.mjs`, lee el manifiesto de Vite y mide en gzip):
  JS inicial sin 3D ≤ 250 KB y bloque 3D ≤ 400 KB. Falla si la escena entra en el JS inicial o deja de
  ser un bloque dinámico.
- **Lighthouse** (`web/scripts/lighthouse.mjs`, `npm run perf`): CLI fijada `lighthouse@13.6.0` por
  `npx`, mediana de 3 pasadas, contra el build servido por `tests/portal_fixture.py`. El script
  arranca el Chromium de Playwright y Lighthouse solo se conecta (`--port`): en WSL, chrome-launcher
  ignora `--chrome-path` y abre el Chrome de Windows. **Revisado en T8c (decisión de Juan): la medida
  que vale es la de CI** (job `lighthouse` de `ci.yml`, tras `web`), perfiles móvil y escritorio, y
  falla si no se cumple: móvil ≥ 90 en Detalle, Fuentes y Administración y ≥ 85 en Hoy y Métricas;
  escritorio ≥ 90 en las 5. Deja `summary.json` y los informes como artefacto
  (`actions/upload-artifact` v7.0.2, fijada por SHA). En WSL solo orienta. En el runner no hay GPU:
  se arranca Chromium con `--enable-unsafe-swiftshader` (WebGL por software). **Revisado en T8d
  (decisión de Juan):** con WebGL por software Hoy se queda en SVG (ver abajo), así que en CI se mide
  el SVG con umbral; el resumen dice con qué se midió (`render`) y añade Hoy móvil con la escena
  forzada (`?escena=forzar`, `forced`) solo como dato, sin umbral. Por defecto se mide el montaje base
  del fixture (comparable con T8b); `VS_PERF_VOLUME` permite medir con volumen.
- **WebGL por software → SVG (T8d, decisión de Juan).** CI dio Hoy móvil 73 (TBT 1 450 ms) con la
  escena sobre SwiftShader. No se cambia el umbral: se corrige lo que también le pasaría a una
  persona. `webglTier` (`web/src/lib/capabilities.ts`) clasifica el contexto: si no sale con
  `failIfMajorPerformanceCaveat` o el renderizador (`WEBGL_debug_renderer_info`, o `RENDERER`)
  es SwiftShader, llvmpipe, softpipe, «Software» o «Microsoft Basic Render», es **software** y la
  escena no se pide. `?escena=forzar` (sin enlace en ningún sitio) la carga igualmente, solo para
  medirla y probarla en CI.
- **Coste de arranque de la escena (T8d)**, para móviles con GPU: se monta por fases (lienzo, embudo,
  plataformas, partículas), dejando pintar un fotograma y cediendo el hilo (`scheduler.yield` o
  `setTimeout`) entre fases, para que los shaders de cada una se compilen en tareas distintas; va a
  30 fps (`frameloop="demand"` y un fotograma pedido cada 1/30 s); y con pantalla < 768 px o
  `hardwareConcurrency` ≤ 4 es «ligera»: como mucho 200 partículas (las alertas, siempre), esferas con
  menos segmentos y `dpr` 1.
- El servidor de fixtures sirve con gzip HTML, JS, CSS y JSON, como el borde: sin eso Lighthouse mide
  el JS sin comprimir.

## Versiones y licencias

Comprobadas el 2026-11-26 en el registro npm (`npm view <paquete> version license`; `version` es la
etiqueta `latest`). URL de cada paquete: `https://www.npmjs.com/package/<paquete>`.

| Paquete | Versión fijada | Licencia | Uso |
|---|---|---|---|
| motion | 14.14.0 | MIT | ejecución (inicial) |
| three | 0.187.0 | MIT | ejecución (bloque 3D) |
| @react-three/fiber | 9.8.2 | MIT | ejecución (bloque 3D); par `react >=19 <19.4` (hay 19.3.1) |
| @react-three/drei | 10.7.9 | MIT | ejecución (bloque 3D, solo `Html`) |
| @types/three | 0.187.0 | MIT | tipos |
| Magic UI (componentes copiados) | registro, 2026-11-26 | MIT | código del repo |
| lighthouse (CLI por `npx`, no es dependencia) | 13.6.0 | Apache-2.0 | medición local |

Magic UI: `https://raw.githubusercontent.com/magicuidesign/magicui/main/LICENSE.md`, leída el
2026-11-26: «MIT License / Copyright (c) Magic UI / Permission is hereby granted, free of charge, to
any person obtaining a copy of this software…».

Dependencias transitivas nuevas (57 paquetes, `package-lock.json`): todas MIT, ISC, BSD o Apache-2.0
salvo `webgl-constants` 1.1.1 (vía `detect-gpu`, de drei), que no declara `license` en su
`package.json` pero trae `LICENSE` MIT («MIT License / Copyright (c) 2019 Tim van Scherpenzeel»).

## Alternativas descartadas

- (T8b) Cargar la escena 3D en cuanto el navegador queda libre: en las pruebas de T8b entraba dentro de
  la carga y hundía Hoy en WSL (Lighthouse 56–72 con la escena; 92–94 sin ella). T8b la dejó tras la
  primera interacción; Juan lo revisó en T8c (viva al llegar, umbral de Hoy en móvil 85, medido en CI).
- (T8c) Bloom de `@react-three/postprocessing`: ver «Dirección de arte»; el sprite aditivo da el
  brillo sin librería nueva.
- `layoutId` de Motion para mover una alerta de tarjeta al cambiar de nivel: necesita `domMax` (más JS
  inicial) y mide el DOM en cada render. Se usa una clave por nivel y la entrada por CSS.
- Texto 3D (drei `Text`): troika descarga una fuente de un CDN si no se le da una. Las etiquetas van
  con `Html` (DOM).

## Consecuencias

- La escena aparece sola poco después de cargar (T8c). Hasta entonces, y con menos movimiento, sin
  WebGL o con WebGL por software (T8d), el SVG estático con las mismas cifras.
- (T8d) El job de CI no mide la escena con umbral: sin GPU mide el SVG. El dato de la escena forzada
  sobre SwiftShader es el caso pesimista y queda en el resumen, sin umbral.
- Lighthouse: en T8b Métricas no llegaba a 90 en móvil (79–87 en WSL). Con los umbrales de T8c
  (Métricas ≥ 85 en móvil) el juez es el job de CI; las cifras de WSL de T8c, en su informe.
- Compresión en Workers: queda como comprobación del primer despliegue, en el runbook
  (`infra/README.md`, decisión de Juan en T8c).
- El manifiesto de Vite (`dist/.vite/manifest.json`) va en el build; solo lista nombres de ficheros.
- Control nuevo: CTL-025 frente a THR-021.
- Compresión en Cloudflare: la página general
  (https://developers.cloudflare.com/speed/optimization/content/compression/, leída el 2026-11-26 con
  un subagente) dice «Cloudflare supports Gzip, Brotli, and Zstandard compression when delivering
  content to website visitors» e incluye `application/javascript`, `text/css` y `application/json`.
  Que se aplique a Workers static assets: **SIN VERIFICAR** (las páginas de static assets no lo dicen).
  Se comprueba con `curl -H 'Accept-Encoding: br, gzip' -sI` tras el primer despliegue.

## Evidencia

- Registro npm, 2026-11-26. Registro de Magic UI y su LICENSE, 2026-11-26.
- Trazas de Chrome con CPU ×4 y Lighthouse 13.6.0 sobre el build, 2026-11-26 (informe de T8b).
- Decisión de stack: Juan, tarea T8b de la noche del 2026-11-25.
- Decisiones de carga de la escena, umbrales de Lighthouse en CI y compresión: Juan (por la sesión
  directora), tarea T8c, 2026-11-26.
- WebGL por software → SVG, arranque por fases, 30 fps y medida forzada sin umbral: Juan (por la
  sesión directora), tarea T8d, a partir del job `lighthouse` del PR #4 (run 45847865191).
- `actions/upload-artifact`: última release `v7.0.2` (publicada el 2026-10-07, no preliminar) y SHA
  `cf430e030ddbb5b0abf93d22962f4752f3646cd9`, leídos en `https://api.github.com/repos/actions/upload-artifact/releases/latest`
  y `…/git/ref/tags/v7.0.2` el 2026-11-26.
