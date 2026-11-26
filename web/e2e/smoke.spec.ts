import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

/**
 * Prueba de humo de las 5 pantallas contra la API real (T6) con fixtures: cada pantalla carga,
 * muestra sus datos y axe no encuentra violaciones graves (serious/critical), en tema oscuro (por
 * defecto) y en claro. Ninguna petición sale de 127.0.0.1.
 */

const SCREENS = [
  { name: "Hoy", path: "/", ready: (p: Page) => expect(p.getByTestId("level-A").getByText("VS-CVE-2099-1001")).toBeVisible() },
  {
    name: "Detalle de alerta",
    path: "/alertas/VS-CVE-2099-1001",
    ready: (p: Page) => expect(p.getByTestId("timeline")).toBeVisible(),
  },
  { name: "Métricas", path: "/metricas", ready: (p: Page) => expect(p.locator(".recharts-surface").first()).toBeVisible() },
  { name: "Fuentes", path: "/fuentes", ready: (p: Page) => expect(p.getByTestId("access-notice")).toBeVisible() },
  { name: "Administración", path: "/admin", ready: (p: Page) => expect(p.getByTestId("access-notice")).toBeVisible() },
];

const GRAVE = new Set(["serious", "critical"]);

async function graveViolations(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  return results.violations
    .filter((v) => GRAVE.has(v.impact ?? ""))
    .map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`);
}

/** Peticiones fuera de 127.0.0.1 y errores de JavaScript de la página. */
function watch(page: Page) {
  const foreign: string[] = [];
  const errors: string[] = [];
  page.on("request", (req) => {
    if (new URL(req.url()).hostname !== "127.0.0.1") foreign.push(req.url());
  });
  page.on("pageerror", (err) => errors.push(err.message));
  return { foreign, errors };
}

for (const theme of ["dark", "light"] as const) {
  for (const s of SCREENS) {
    test(`${s.name} (${theme}) carga y pasa axe`, async ({ page }) => {
      const seen = watch(page);
      await page.addInitScript((t) => window.localStorage.setItem("vs-theme", t), theme);
      await page.goto(s.path);
      await s.ready(page);
      await expect(page.getByRole("heading", { level: 1 })).toHaveText(
        s.name === "Detalle de alerta" ? /VS-CVE-2099-1001/ : s.name,
      );
      const dark = await page.evaluate(() => document.documentElement.classList.contains("dark"));
      expect(dark).toBe(theme === "dark");
      expect(await graveViolations(page)).toEqual([]);
      expect(seen.foreign).toEqual([]);
      expect(seen.errors).toEqual([]);
    });
  }
}

test("Hoy enseña A, B y C del día y enlaza al detalle", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByTestId("level-A")).toContainText("VS-CVE-2099-1001");
  await expect(page.getByTestId("level-B")).toContainText("VS-CVE-2099-1005");
  await expect(page.getByTestId("level-C")).toContainText("VS-CVE-2099-1004");
  // Las CVE `none` y la de A restringido no son alertas del feed público.
  await expect(page.getByText("VS-CVE-2099-1002")).toHaveCount(0);
  await page.getByTestId("level-A").getByRole("link", { name: "VS-CVE-2099-1001" }).click();
  await expect(page).toHaveURL(/\/alertas\/VS-CVE-2099-1001$/);
  await expect(page.getByTestId("timeline")).toContainText("Entra en CISA KEV");
});

test("la API con fixtures no sirve datos restringidos al portal", async ({ request }) => {
  const resp = await request.get("/v1/feed/alerts/latest.json");
  expect(resp.ok()).toBe(true);
  expect(await resp.text()).not.toContain("RESTRICTED-PAYLOAD-DO-NOT-PUBLISH");
});
