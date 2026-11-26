#!/usr/bin/env node
/**
 * Lighthouse sobre el build (T8b; umbrales de T8c, ADR-0024). Arranca la API de T6 con fixtures
 * sirviendo `dist` en 127.0.0.1 (como la prueba de humo), pasa Lighthouse (CLI fijada, con el
 * Chromium de Playwright) por las 5 pantallas en los perfiles móvil y escritorio, toma la MEDIANA
 * de 3 pasadas por pantalla y perfil, deja un resumen JSON y falla si no se cumplen los umbrales.
 *
 * Umbrales (decisión de Juan, T8c): móvil ≥ 90 en Detalle, Fuentes y Administración y ≥ 85 en Hoy
 * y Métricas; escritorio ≥ 90 en las 5. La medida que vale es la de CI (máquina estable); en WSL
 * solo orienta.
 *
 * Uso: `npm run build && npm run perf [-- dir_de_salida]`. Los informes y `summary.json` van a ese
 * directorio (por defecto `../local/tmp/lighthouse`, ignorado por git).
 *
 * Variables (todas opcionales):
 * - `VS_PERF_PROFILES`: `mobile,desktop` (por defecto) o uno de los dos.
 * - `VS_PERF_RUNS`: pasadas por pantalla (3).
 * - `VS_PERF_VOLUME`: CVE sintéticas extra del fixture (0 = montaje base, como T8b).
 * - `VS_PERF_CHROME_FLAGS`: banderas extra del navegador, separadas por espacios. Siempre va
 *   `--enable-unsafe-swiftshader`: sin GPU hay WebGL, pero por software.
 * - `VS_PERF_FORCED=0`: no hacer la medida extra de Hoy móvil con la escena forzada.
 *
 * Escena o SVG (T8d, decisión de Juan): con WebGL por software (SwiftShader en CI, sin GPU) Hoy se
 * queda en SVG, como lo vería una persona sin GPU, y eso es lo que se mide con umbral. `summary.json`
 * anota en cada fila de Hoy con qué se midió (`render`: `escena 3D` o `SVG`). Además, si el perfil
 * móvil está incluido, se mide Hoy móvil con `?escena=forzar` (parámetro de prueba): solo como dato,
 * en `forced`, **sin umbral**.
 */
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { chromium } from "@playwright/test";

const LIGHTHOUSE = "lighthouse@13.6.0";
const PORT = Number(process.env.VS_PERF_PORT ?? 8788);
const BASE = `http://127.0.0.1:${PORT}`;
const CDP_PORT = Number(process.env.VS_PERF_CDP_PORT ?? 9333);
const RUNS = Number(process.env.VS_PERF_RUNS ?? 3);
const VOLUME = Number(process.env.VS_PERF_VOLUME ?? 0);
const PROFILES = (process.env.VS_PERF_PROFILES ?? "mobile,desktop").split(",").map((p) => p.trim());
// SwiftShader (WebGL por software) solo entra si no hay GPU. El portal lo detecta y se queda en SVG;
// la medida forzada lo usa para pintar la escena sin GPU.
const CHROME_FLAGS = ["--enable-unsafe-swiftshader", ...(process.env.VS_PERF_CHROME_FLAGS ?? "").split(/\s+/).filter(Boolean)];
const FORCED = process.env.VS_PERF_FORCED !== "0";
/** Parámetro de prueba del portal (`web/src/lib/capabilities.ts`): carga la escena aunque no haya GPU. */
const FORCE_QUERY = "?escena=forzar";
const ROOT = path.resolve(import.meta.dirname, "..", "..");
const OUT = path.resolve(process.argv[2] ?? path.join(ROOT, "local", "tmp", "lighthouse"));

const SCREENS = [
  { slug: "hoy", path: "/" },
  { slug: "detalle", path: "/alertas/VS-CVE-2099-1001" },
  { slug: "metricas", path: "/metricas" },
  { slug: "fuentes", path: "/fuentes" },
  { slug: "administracion", path: "/gestion" },
];

/** Rendimiento mínimo por perfil y pantalla (T8c). */
export const THRESHOLDS = {
  mobile: { hoy: 85, detalle: 90, metricas: 85, fuentes: 90, administracion: 90 },
  desktop: { hoy: 90, detalle: 90, metricas: 90, fuentes: 90, administracion: 90 },
};

async function waitFor(url, ms = 60_000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      /* todavía no */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`el servidor no respondió en ${url}`);
}

/** ¿Pidió la página el bloque de la escena 3D? (sin GPU o sin WebGL no se pide y se mide el SVG). */
function sceneLoaded(report) {
  const items = report.audits["network-requests"]?.details?.items ?? [];
  return items.some((i) => /FunnelScene-/.test(i.url ?? ""));
}

function lighthouse(url, profile, out) {
  const r = spawnSync(
    "npx",
    [
      "--yes",
      LIGHTHOUSE,
      url,
      "--hostname=127.0.0.1",
      `--port=${CDP_PORT}`,
      "--only-categories=performance,accessibility",
      ...(profile === "desktop" ? ["--preset=desktop"] : []),
      "--output=json",
      `--output-path=${out}`,
      "--quiet",
    ],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  if (r.status !== 0) throw new Error(`Lighthouse falló en ${url} (${profile})`);
  return JSON.parse(readFileSync(out, "utf8"));
}

/**
 * `RUNS` pasadas de Lighthouse sobre `url`; devuelve la fila de la pasada mediana por rendimiento
 * (Lighthouse varía de una pasada a otra). En Hoy anota si se midió la escena 3D o el SVG.
 */
function measure(url, profile, dir, slug) {
  const reports = [];
  for (let run = 1; run <= RUNS; run++) {
    reports.push(lighthouse(url, profile, path.join(dir, `${slug}-${run}.json`)));
  }
  reports.sort((a, b) => a.categories.performance.score - b.categories.performance.score);
  const report = reports[Math.floor(reports.length / 2)];
  const m = (id) => report.audits[id]?.displayValue ?? "?";
  const scene3d = slug.startsWith("hoy") ? sceneLoaded(report) : undefined;
  return {
    profile,
    screen: slug,
    performance: Math.round(report.categories.performance.score * 100),
    accessibility: Math.round(report.categories.accessibility.score * 100),
    // benchmarkIndex: cuánto corre la CPU al medir (más alto, más rápida). Si baja mucho, la
    // máquina está ocupada y la puntuación no es comparable.
    runs: reports.map((x) => ({
      performance: Math.round(x.categories.performance.score * 100),
      benchmarkIndex: Math.round(x.environment?.benchmarkIndex ?? 0),
    })),
    scene3d,
    render: scene3d === undefined ? undefined : scene3d ? "escena 3D" : "SVG",
    fcp: m("first-contentful-paint"),
    lcp: m("largest-contentful-paint"),
    tbt: m("total-blocking-time"),
    cls: m("cumulative-layout-shift"),
  };
}

function line(row) {
  return (
    `${row.profile.padEnd(7)} ${row.screen.padEnd(15)} rendimiento ${row.performance} (pasadas ` +
    `${row.runs.map((r) => `${r.performance}@bi${r.benchmarkIndex}`).join(" ")}) · accesibilidad ${row.accessibility} · ` +
    `FCP ${row.fcp} · LCP ${row.lcp} · TBT ${row.tbt} · CLS ${row.cls}` +
    (row.render ? ` · con ${row.render}` : "")
  );
}

async function main() {
  for (const p of PROFILES) if (!THRESHOLDS[p]) throw new Error(`perfil desconocido: ${p}`);
  mkdirSync(OUT, { recursive: true });
  const server = spawn(
    "uv",
    ["run", "python", "-m", "tests.portal_fixture", "--port", String(PORT), "--static", "web/dist", "--volume", String(VOLUME)],
    { cwd: ROOT, stdio: ["ignore", "ignore", "inherit"] },
  );
  // El navegador lo arranca este script y Lighthouse solo se conecta (`--port`): así no entra
  // chrome-launcher, que en WSL busca el Chrome de Windows aunque se le dé otra ruta.
  const profileDir = path.join(OUT, "profile");
  const browser = spawn(
    chromium.executablePath(),
    [
      "--headless=new",
      "--no-sandbox",
      `--remote-debugging-port=${CDP_PORT}`,
      `--user-data-dir=${profileDir}`,
      ...CHROME_FLAGS,
      "about:blank",
    ],
    { stdio: "ignore" },
  );
  const summary = {
    lighthouse: LIGHTHOUSE,
    runs: RUNS,
    volume: VOLUME,
    chromeFlags: CHROME_FLAGS,
    thresholds: THRESHOLDS,
    results: [],
    // Hoy móvil con la escena forzada: solo dato, sin umbral (T8d).
    forced: null,
  };
  let failed = false;
  try {
    await waitFor(`${BASE}/v1/feed/alerts/latest.json`);
    await waitFor(`http://127.0.0.1:${CDP_PORT}/json/version`);
    for (const profile of PROFILES) {
      const dir = path.join(OUT, profile);
      mkdirSync(dir, { recursive: true });
      for (const s of SCREENS) {
        const min = THRESHOLDS[profile][s.slug];
        const row = { ...measure(`${BASE}${s.path}`, profile, dir, s.slug), min };
        row.pass = row.performance >= min;
        failed ||= !row.pass;
        summary.results.push(row);
        console.log(`${row.pass ? "OK " : "MAL"} ${line(row)} (mínimo ${min})`);
      }
    }
    if (FORCED && PROFILES.includes("mobile")) {
      const dir = path.join(OUT, "mobile");
      const row = measure(`${BASE}/${FORCE_QUERY}`, "mobile", dir, "hoy-forzada");
      summary.forced = { ...row, query: FORCE_QUERY, threshold: null };
      console.log(`DATO ${line(row)} (escena forzada con ${FORCE_QUERY}; sin umbral)`);
      if (!row.scene3d) console.log("     ojo: la medida forzada no pidió la escena (¿sin WebGL?)");
    }
  } finally {
    browser.kill();
    server.kill();
    summary.failed = failed;
    writeFileSync(path.join(OUT, "summary.json"), JSON.stringify(summary, null, 2));
  }
  if (failed) {
    console.error("Rendimiento por debajo del umbral en al menos una pantalla (ver summary.json).");
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
