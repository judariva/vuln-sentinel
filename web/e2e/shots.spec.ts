import { expect, test } from "@playwright/test";
import path from "node:path";

/**
 * Capturas de las 5 pantallas en oscuro y claro, con y sin movimiento (`prefers-reduced-motion`).
 * `npm run shots`. No se versionan: van a `VS_SHOTS_DIR` o a `local/tmp/shots` (ignorado por git).
 */
const DIR = process.env.VS_SHOTS_DIR ?? path.resolve(import.meta.dirname, "..", "..", "local", "tmp", "shots");

const SCREENS = [
  { slug: "hoy", path: "/", ready: "level-A" },
  { slug: "detalle", path: "/alertas/VS-CVE-2099-1001", ready: "timeline" },
  { slug: "metricas", path: "/metricas", ready: null },
  { slug: "fuentes", path: "/fuentes", ready: "access-notice" },
  { slug: "administracion", path: "/gestion", ready: "access-notice" },
];

for (const theme of ["dark", "light"] as const) {
  for (const motion of ["movimiento", "reducido"] as const) {
    for (const s of SCREENS) {
      test(`${s.slug} ${theme} ${motion}`, async ({ page }) => {
        test.setTimeout(60_000);
        await page.setViewportSize({ width: 1280, height: 900 });
        await page.emulateMedia({ reducedMotion: motion === "reducido" ? "reduce" : "no-preference" });
        await page.addInitScript((t) => window.localStorage.setItem("vs-theme", t), theme);
        await page.goto(s.path);
        if (s.ready) await expect(page.getByTestId(s.ready)).toBeVisible();
        else await expect(page.locator(".recharts-surface").first()).toBeVisible();
        // Mover el ratón despierta la escena 3D (Hoy) y desplazarse monta las gráficas (Métricas).
        await page.mouse.move(640, 300);
        await page.mouse.wheel(0, 4000);
        await page.waitForTimeout(800);
        await page.mouse.wheel(0, -4000);
        if (s.slug === "hoy" && motion === "movimiento") {
          // Con WebGL, la escena 3D; se espera a que las alertas caigan sobre su plataforma.
          await expect(page.getByTestId("funnel-3d")).toBeVisible({ timeout: 15_000 });
          await page.waitForTimeout(9000);
        } else {
          await page.waitForTimeout(1500);
        }
        await page.screenshot({ path: path.join(DIR,`${s.slug}-${theme}-${motion}.png`), fullPage: true });
      });
    }
  }
}
