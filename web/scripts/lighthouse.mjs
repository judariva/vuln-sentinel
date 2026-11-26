#!/usr/bin/env node
/**
 * Lighthouse sobre el build (T8b, ADR-0024). Arranca la API de T6 con fixtures sirviendo `dist`
 * en 127.0.0.1 (como la prueba de humo), pasa Lighthouse (CLI fijada, con el Chromium de
 * Playwright) por las 5 pantallas y falla si el rendimiento de una pantalla de DATOS (las que leen
 * la API: Hoy, Detalle y Métricas) baja de 90. Perfil por defecto de Lighthouse (móvil, con
 * limitación simulada).
 *
 * Uso: `npm run build && npm run perf [-- dir_de_salida]`. Los informes JSON van a ese directorio
 * (por defecto `../local/tmp/lighthouse`, ignorado por git).
 */
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { chromium } from "@playwright/test";

const LIGHTHOUSE = "lighthouse@13.6.0";
const PORT = Number(process.env.VS_PERF_PORT ?? 8788);
const BASE = `http://127.0.0.1:${PORT}`;
const CDP_PORT = Number(process.env.VS_PERF_CDP_PORT ?? 9333);
const MIN_PERF = 90;
const RUNS = Number(process.env.VS_PERF_RUNS ?? 3);
const PRESET = process.env.VS_PERF_PRESET;
const ROOT = path.resolve(import.meta.dirname, "..", "..");
const OUT = path.resolve(process.argv[2] ?? path.join(ROOT, "local", "tmp", "lighthouse"));

const SCREENS = [
  { slug: "hoy", path: "/", data: true },
  { slug: "detalle", path: "/alertas/VS-CVE-2099-1001", data: true },
  { slug: "metricas", path: "/metricas", data: true },
  { slug: "fuentes", path: "/fuentes", data: false },
  { slug: "administracion", path: "/gestion", data: false },
];

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

async function main() {
  mkdirSync(OUT, { recursive: true });
  const server = spawn("uv", ["run", "python", "-m", "tests.portal_fixture", "--port", String(PORT), "--static", "web/dist"], {
    cwd: ROOT,
    stdio: ["ignore", "ignore", "inherit"],
  });
  // El navegador lo arranca este script y Lighthouse solo se conecta (`--port`): así no entra
  // chrome-launcher, que en WSL busca el Chrome de Windows aunque se le dé otra ruta.
  const profile = path.join(OUT, "profile");
  const browser = spawn(
    chromium.executablePath(),
    ["--headless=new", "--no-sandbox", `--remote-debugging-port=${CDP_PORT}`, `--user-data-dir=${profile}`, "about:blank"],
    { stdio: "ignore" },
  );
  let failed = false;
  try {
    await waitFor(`${BASE}/v1/feed/alerts/latest.json`);
    await waitFor(`http://127.0.0.1:${CDP_PORT}/json/version`);
    for (const s of SCREENS) {
      // Lighthouse varía de una pasada a otra (en esta máquina, ±10 puntos): se toma la pasada
      // mediana por rendimiento.
      const reports = [];
      for (let run = 1; run <= RUNS; run++) {
        const out = path.join(OUT, `${s.slug}-${run}.json`);
        const r = spawnSync(
          "npx",
          [
            "--yes",
            LIGHTHOUSE,
            `${BASE}${s.path}`,
            "--hostname=127.0.0.1",
            `--port=${CDP_PORT}`,
            "--only-categories=performance,accessibility",
            // Por defecto, el perfil móvil de Lighthouse (el criterio de T8b). `VS_PERF_PRESET=desktop`
            // solo para comparar.
            ...(PRESET ? [`--preset=${PRESET}`] : []),
            "--output=json",
            `--output-path=${out}`,
            "--quiet",
          ],
          { stdio: ["ignore", "ignore", "inherit"] },
        );
        if (r.status !== 0) throw new Error(`Lighthouse falló en ${s.path}`);
        reports.push(JSON.parse(readFileSync(out, "utf8")));
      }
      reports.sort((a, b) => a.categories.performance.score - b.categories.performance.score);
      const report = reports[Math.floor(reports.length / 2)];
      // benchmarkIndex: cuánto corre la CPU de esta máquina al medir (más alto, más rápida). Si
      // baja mucho, la máquina está ocupada y la puntuación no es comparable.
      const all = reports
        .map((x) => `${Math.round(x.categories.performance.score * 100)}@bi${Math.round(x.environment?.benchmarkIndex ?? 0)}`)
        .join(" ");
      const perf = Math.round(report.categories.performance.score * 100);
      const a11y = Math.round(report.categories.accessibility.score * 100);
      const m = (id) => report.audits[id]?.displayValue ?? "?";
      const pass = !s.data || perf >= MIN_PERF;
      failed ||= !pass;
      console.log(
        `${pass ? "OK " : "MAL"} ${s.slug.padEnd(15)} rendimiento ${perf} (pasadas ${all}) · accesibilidad ${a11y} · ` +
          `FCP ${m("first-contentful-paint")} · LCP ${m("largest-contentful-paint")} · TBT ${m("total-blocking-time")} · CLS ${m("cumulative-layout-shift")}` +
          (s.data ? "" : " (pantalla de ejemplo, no cuenta)"),
      );
    }
  } finally {
    browser.kill();
    server.kill();
  }
  if (failed) {
    console.error(`Rendimiento por debajo de ${MIN_PERF} en una pantalla de datos.`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
