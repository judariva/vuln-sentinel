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
  { name: "Administración", path: "/gestion", ready: (p: Page) => expect(p.getByTestId("access-notice")).toBeVisible() },
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
  // Las CVE `none` y la de A restringido no son alertas del feed público: no salen en las tarjetas
  // ni en los cambios. (Sí son partículas grises del embudo, que pinta el feed completo, T8b.)
  for (const where of [
    page.getByTestId("level-A"),
    page.getByTestId("level-B"),
    page.getByTestId("level-C"),
    page.getByRole("region", { name: /Cambios del día/ }),
  ]) {
    await expect(where.getByText("VS-CVE-2099-1002")).toHaveCount(0);
    await expect(where.getByText("VS-CVE-2099-1003")).toHaveCount(0);
  }
  await page.getByTestId("level-A").getByRole("link", { name: "VS-CVE-2099-1001" }).click();
  await expect(page).toHaveURL(/\/alertas\/VS-CVE-2099-1001$/);
  await expect(page.getByTestId("timeline")).toContainText("Entra en CISA KEV");
});

/** Lo que el embudo debe enseñar, calculado aquí directamente de la API (no del portal). */
async function expectedFunnel(request: import("@playwright/test").APIRequestContext) {
  const page = await (await request.get("/v1/feed/all/changes")).json();
  const latest = await (await request.get("/v1/feed/alerts/latest.json")).json();
  const day = String(page.generated_at).slice(0, 10);
  const current = new Map<string, string>(latest.alerts.map((a: { id: string; level: string }) => [a.id, a.level]));
  const last = new Map<string, { modified: string; level: string }>();
  for (const e of page.entries as { id: string; modified: string; level: string }[]) {
    if (!e.modified.startsWith(day)) continue;
    const prev = last.get(e.id);
    if (!prev || e.modified >= prev.modified) last.set(e.id, e);
  }
  const levels = [...last.entries()].map(([id, e]) => current.get(id) ?? e.level);
  return { total: last.size, alerts: levels.filter((l) => l === "A" || l === "B" || l === "C").length, hasMore: page.has_more };
}

test("Hoy: el embudo enseña las cifras de la API y las alertas no lo esperan", async ({ page, request }) => {
  const want = await expectedFunnel(request);
  expect(want.hasMore).toBe(false);
  expect(want.total).toBeGreaterThan(0);
  await page.goto("/");
  await expect(page.getByTestId("level-A")).toContainText("VS-CVE-2099-1001");
  const funnel = page.getByTestId("funnel");
  await expect(funnel).toHaveAttribute("data-total", String(want.total));
  await expect(funnel).toHaveAttribute("data-complete", "true");
  const label = await funnel.locator('[role="img"]').first().getAttribute("aria-label");
  expect(label).toContain(`${want.total} CVE con cambios`);
  // El KPI de alertas del embudo coincide con la API.
  await expect(funnel.locator(`[data-value="${want.alerts}"]`)).toHaveCount(1);
});

test("con prefers-reduced-motion el embudo es SVG estático y la escena 3D no se descarga", async ({ page }) => {
  const scene: string[] = [];
  page.on("request", (r) => {
    if (/FunnelScene/.test(r.url())) scene.push(r.url());
  });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  await expect(page.getByTestId("funnel-static")).toBeVisible();
  await page.mouse.move(200, 200);
  await page.mouse.move(400, 300);
  await page.waitForTimeout(2500);
  await expect(page.getByTestId("funnel-3d")).toHaveCount(0);
  expect(scene).toEqual([]);
});

test("si el bloque 3D no llega, los datos y el SVG siguen ahí", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  let asked = false;
  await page.route(/FunnelScene-.*\.js$/, (route) => {
    asked = true;
    return route.abort();
  });
  await page.goto("/");
  await expect(page.getByTestId("level-A")).toContainText("VS-CVE-2099-1001");
  await page.mouse.move(200, 200);
  await page.mouse.move(400, 300);
  await page.waitForTimeout(2500);
  await expect(page.getByTestId("funnel-static")).toBeVisible();
  await expect(page.getByTestId("level-C")).toContainText("VS-CVE-2099-1004");
  expect(errors).toEqual([]);
  // Solo vale si de verdad se pidió el bloque (con WebGL); sin WebGL, ni se pide.
  const webgl = await page.evaluate(() => !!document.createElement("canvas").getContext("webgl"));
  expect(asked).toBe(webgl);
});

test("sin interacción, la escena 3D no se descarga: primero los datos", async ({ page }) => {
  const scene: string[] = [];
  page.on("request", (r) => {
    if (/FunnelScene/.test(r.url())) scene.push(r.url());
  });
  await page.goto("/");
  await expect(page.getByTestId("funnel-static")).toBeVisible();
  await page.waitForTimeout(2500);
  expect(scene).toEqual([]);
});

test("con WebGL, la escena 3D se carga aparte y enseña la CVE al pasar el ratón", async ({ page }) => {
  const webgl = await page.evaluate(() => {
    const c = document.createElement("canvas");
    return !!(c.getContext("webgl2") ?? c.getContext("webgl"));
  });
  test.skip(!webgl, "este Chromium no tiene WebGL: se ve la versión estática (probada arriba)");
  await page.goto("/");
  await expect(page.getByTestId("funnel-static")).toBeVisible();
  await page.mouse.move(100, 100);
  const scene = page.getByTestId("funnel-3d");
  await expect(scene).toBeVisible({ timeout: 15_000 });
  await expect(scene.locator("canvas")).toBeVisible();
  // La etiqueta de cada plataforma lleva la cifra de la API.
  await expect(scene.getByTestId("funnel-pad-A")).toHaveText("A · 1");
  // La alerta de A acaba sobre su plataforma (a la izquierda de la etiqueta): se busca con el ratón.
  test.setTimeout(90_000);
  await page.waitForTimeout(9000);
  const pad = (await scene.getByTestId("funnel-pad-A").boundingBox())!;
  let seen = "";
  for (let y = pad.y - 20; y < pad.y + 30 && !seen; y += 3) {
    for (let x = pad.x - 140; x < pad.x && !seen; x += 3) {
      await page.mouse.move(x, y);
      seen = await page.evaluate(() => document.querySelector('[data-testid="funnel-tooltip"]')?.textContent ?? "");
    }
  }
  expect(seen).toBe("VS-CVE-2099-1001 · Nivel A · explotación activa");
});

test("la API con fixtures no sirve datos restringidos al portal", async ({ request }) => {
  const resp = await request.get("/v1/feed/alerts/latest.json");
  expect(resp.ok()).toBe(true);
  expect(await resp.text()).not.toContain("RESTRICTED-PAYLOAD-DO-NOT-PUBLISH");
});
