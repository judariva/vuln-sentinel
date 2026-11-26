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
 *   `--enable-unsafe-swiftshader`, para que haya WebGL sin GPU y se mida la escena 3D.
 * - `VS_PERF_ALLOW_NO_SCENE=1`: no fallar si Hoy se midió sin la escena 3D (por defecto, falla).
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
// SwiftShader (WebGL por software) solo entra si no hay GPU; sin él, el Chromium sin cabeza no tiene
// WebGL en CI ni en WSL y Hoy se mediría con el SVG, no con la escena que ve quien tiene WebGL.
const CHROME_FLAGS = ["--enable-unsafe-swiftshader", ...(process.env.VS_PERF_CHROME_FLAGS ?? "").split(/\s+/).filter(Boolean)];
// Si Hoy se mide sin la escena 3D, la cifra no vale y el script falla (salvo que se pida lo contrario).
const ALLOW_NO_SCENE = process.env.VS_PERF_ALLOW_NO_SCENE === "1";
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

/** ¿Pidió la página el bloque de la escena 3D? (si no hubo WebGL, no se pide y se mide el SVG). */
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
  };
  let failed = false;
  try {
    await waitFor(`${BASE}/v1/feed/alerts/latest.json`);
    await waitFor(`http://127.0.0.1:${CDP_PORT}/json/version`);
    for (const profile of PROFILES) {
      const dir = path.join(OUT, profile);
      mkdirSync(dir, { recursive: true });
      for (const s of SCREENS) {
        // Lighthouse varía de una pasada a otra: se toma la pasada mediana por rendimiento.
        const reports = [];
        for (let run = 1; run <= RUNS; run++) {
          reports.push(lighthouse(`${BASE}${s.path}`, profile, path.join(dir, `${s.slug}-${run}.json`)));
        }
        reports.sort((a, b) => a.categories.performance.score - b.categories.performance.score);
        const report = reports[Math.floor(reports.length / 2)];
        const perf = Math.round(report.categories.performance.score * 100);
        const a11y = Math.round(report.categories.accessibility.score * 100);
        const min = THRESHOLDS[profile][s.slug];
        const scene3d = s.slug === "hoy" ? sceneLoaded(report) : undefined;
        const pass = perf >= min && (scene3d !== false || ALLOW_NO_SCENE);
        failed ||= !pass;
        const m = (id) => report.audits[id]?.displayValue ?? "?";
        const row = {
          profile,
          screen: s.slug,
          performance: perf,
          min,
          pass,
          accessibility: a11y,
          // benchmarkIndex: cuánto corre la CPU al medir (más alto, más rápida). Si baja mucho, la
          // máquina está ocupada y la puntuación no es comparable.
          runs: reports.map((x) => ({
            performance: Math.round(x.categories.performance.score * 100),
            benchmarkIndex: Math.round(x.environment?.benchmarkIndex ?? 0),
          })),
          scene3d,
          fcp: m("first-contentful-paint"),
          lcp: m("largest-contentful-paint"),
          tbt: m("total-blocking-time"),
          cls: m("cumulative-layout-shift"),
        };
        summary.results.push(row);
        console.log(
          `${pass ? "OK " : "MAL"} ${profile.padEnd(7)} ${s.slug.padEnd(15)} rendimiento ${perf} (mínimo ${min}; pasadas ` +
            `${row.runs.map((r) => `${r.performance}@bi${r.benchmarkIndex}`).join(" ")}) · accesibilidad ${a11y} · ` +
            `FCP ${row.fcp} · LCP ${row.lcp} · TBT ${row.tbt} · CLS ${row.cls}` +
            (row.scene3d === undefined
              ? ""
              : row.scene3d
                ? " · con escena 3D"
                : " · SIN escena 3D (sin WebGL o no llegó a pedirse): la medida no representa Hoy"),
        );
      }
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
