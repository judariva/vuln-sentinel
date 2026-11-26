#!/usr/bin/env node
/**
 * Presupuestos del build (T8b, ADR-0024). Lee `dist/.vite/manifest.json`, mide en gzip y falla
 * (código 1) si se pasan:
 *
 * - JS inicial sin 3D: la entrada y todo lo que importa de forma estática.
 * - Bloque 3D: lo que añade la escena (`FunnelScene.tsx`) y sus importaciones estáticas, sin lo
 *   que ya está en el inicial.
 *
 * Uso: `node scripts/check-budgets.mjs [dist]`.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { gzipSync } from "node:zlib";

const KB = 1024;
export const BUDGETS = { initialKb: 250, sceneKb: 400 };
const SCENE_SRC = "src/components/funnel/FunnelScene.tsx";

export function closure(manifest, keys) {
  const seen = new Set();
  const stack = [...keys];
  while (stack.length) {
    const k = stack.pop();
    if (seen.has(k) || !manifest[k]) continue;
    seen.add(k);
    stack.push(...(manifest[k].imports ?? []));
  }
  return seen;
}

export function measure(dist) {
  const manifest = JSON.parse(readFileSync(path.join(dist, ".vite", "manifest.json"), "utf8"));
  const entries = Object.keys(manifest).filter((k) => manifest[k].isEntry);
  if (entries.length === 0) throw new Error("el manifiesto no tiene entrada");
  if (!manifest[SCENE_SRC]) throw new Error(`la escena 3D (${SCENE_SRC}) no es un bloque aparte`);
  if (!manifest[SCENE_SRC].isDynamicEntry) throw new Error("la escena 3D no se carga de forma dinámica (lazy)");

  const initial = closure(manifest, entries);
  if (initial.has(SCENE_SRC)) throw new Error("la escena 3D está en el JS inicial");
  const scene = [...closure(manifest, [SCENE_SRC])].filter((k) => !initial.has(k));

  const gz = (keys) =>
    [...keys]
      .map((k) => manifest[k].file)
      .filter((f) => f.endsWith(".js"))
      .reduce((n, f) => n + gzipSync(readFileSync(path.join(dist, f)), { level: 9 }).length, 0);

  return {
    initialKb: gz(initial) / KB,
    sceneKb: gz(scene) / KB,
    initialFiles: [...initial].map((k) => manifest[k].file),
    sceneFiles: scene.map((k) => manifest[k].file),
  };
}

function main() {
  const dist = path.resolve(process.argv[2] ?? "dist");
  const m = measure(dist);
  const rows = [
    ["JS inicial (sin 3D)", m.initialKb, BUDGETS.initialKb, m.initialFiles],
    ["Bloque 3D", m.sceneKb, BUDGETS.sceneKb, m.sceneFiles],
  ];
  let ok = true;
  for (const [name, kb, max, files] of rows) {
    const pass = kb <= max;
    ok &&= pass;
    console.log(`${pass ? "OK " : "MAL"} ${name}: ${kb.toFixed(1)} KB gzip (máximo ${max}) · ${files.join(", ")}`);
  }
  if (!ok) {
    console.error("Presupuesto superado.");
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
