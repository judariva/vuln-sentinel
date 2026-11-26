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
- **Robustez.** La escena es otro bloque (`lazy`) y se pide **tras la primera interacción con la
  página** (ratón, tecla, toque, desplazamiento) y con el navegador libre. Medido con CPU ×4: evaluar
  three.js y montar la escena son ~1,7 s de hilo principal; si entra sola al cargar compite con los
  datos. Mientras llega, si falla (error de WebGL o bloque que no llega) y con `prefers-reduced-motion`
  o sin WebGL se ve `FunnelStatic` (SVG) con las mismas cifras. El embudo tiene su propia petición
  (`/v1/feed/all/changes`) y se monta después de pintar las alertas: si falla, solo falla su tarjeta.
- **Rendimiento del resto del portal** (para Lighthouse): todas las pantallas salvo Hoy en bloques
  aparte; en Métricas, Recharts en su propio bloque, cada gráfica se monta al entrar en pantalla y con
  el navegador libre, y sin animación de Recharts (anima volviendo a pintar React en cada fotograma).
  Los datos de la API se pintan en una transición de React (`startTransition`).
- **Presupuestos en CI** (`web/scripts/check-budgets.mjs`, lee el manifiesto de Vite y mide en gzip):
  JS inicial sin 3D ≤ 250 KB y bloque 3D ≤ 400 KB. Falla si la escena entra en el JS inicial o deja de
  ser un bloque dinámico.
- **Lighthouse** (`web/scripts/lighthouse.mjs`, `npm run perf`): CLI fijada `lighthouse@13.6.0` por
  `npx`, perfil móvil por defecto, mediana de 3 pasadas, contra el build servido por
  `tests/portal_fixture.py`. El script arranca el Chromium de Playwright y Lighthouse solo se conecta
  (`--port`): en WSL, chrome-launcher ignora `--chrome-path` y abre el Chrome de Windows. No va en la
  CI (varía demasiado en máquinas compartidas).
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

- Cargar la escena 3D en cuanto el navegador queda libre: en las pruebas entraba dentro de la carga y
  hundía el rendimiento de Hoy (Lighthouse 56–72 con la escena; 92–94 sin ella).
- `layoutId` de Motion para mover una alerta de tarjeta al cambiar de nivel: necesita `domMax` (más JS
  inicial) y mide el DOM en cada render. Se usa una clave por nivel y la entrada por CSS.
- Texto 3D (drei `Text`): troika descarga una fuente de un CDN si no se le da una. Las etiquetas van
  con `Html` (DOM).

## Consecuencias

- En escritorio la escena aparece al mover el ratón; en móvil, al tocar o desplazarse. Quien solo mira
  sin interactuar ve el SVG estático, con las mismas cifras.
- **Lighthouse ≥ 90 no se cumple en Métricas** con el perfil móvil (79–87 con la máquina tranquila).
  Hoy (92–94) y Detalle (95–97) sí. El coste que queda es el render de Recharts. Ver el informe de
  T8b y la pregunta abierta.
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
