import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

/**
 * Prueba de humo de las 5 pantallas contra la API real (T6) con fixtures: cada pantalla carga,
 * muestra sus datos y axe no encuentra violaciones graves (serious/critical), en tema oscuro (por
 * defecto) y en claro. Ninguna petición sale de 127.0.0.1.
 */

/**
 * Hoy con la escena forzada (parámetro de prueba, T8d). El Chromium de Playwright no tiene GPU: con
 * WebGL por software Hoy se queda en SVG, y los tests de la escena la fuerzan para poder probarla.
 */
const FORCED = "/?escena=forzar";

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
  const byLevel = { A: 0, B: 0, C: 0 };
  for (const l of levels) if (l === "A" || l === "B" || l === "C") byLevel[l] += 1;
  return {
    total: last.size,
    alerts: byLevel.A + byLevel.B + byLevel.C,
    byLevel,
    hasMore: page.has_more,
  };
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
  // Los KPI del embudo (en su tarjeta de la rejilla) y las etiquetas de los destinos coinciden con la API.
  const kpi = page.getByTestId("funnel-kpi");
  await expect(kpi.locator("dd").nth(0).locator("[data-value]")).toHaveAttribute("data-value", String(want.total));
  await expect(kpi.locator("dd").nth(1).locator("[data-value]")).toHaveAttribute("data-value", String(want.alerts));
  for (const lv of ["A", "B", "C"] as const) {
    await expect(funnel.getByTestId(`funnel-pad-${lv}`)).toHaveText(`${lv} · ${want.byLevel[lv]}`);
  }
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
  // Forzada: sin GPU (CI, WSL) la escena no se pediría y el test no probaría nada.
  await page.goto(FORCED);
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

test("con WebGL por software (sin GPU) Hoy se queda en SVG y el bloque 3D no se pide", async ({ page }) => {
  const renderer = await page.evaluate(() => {
    const gl = document.createElement("canvas").getContext("webgl");
    const info = gl?.getExtension("WEBGL_debug_renderer_info");
    return gl && info ? String(gl.getParameter(info.UNMASKED_RENDERER_WEBGL)) : "";
  });
  test.skip(!/swiftshader|llvmpipe|software/i.test(renderer), `este Chromium tiene GPU (${renderer}) o no tiene WebGL`);
  const scene: string[] = [];
  page.on("request", (r) => {
    if (/FunnelScene/.test(r.url())) scene.push(r.url());
  });
  await page.goto("/");
  await expect(page.getByTestId("level-A")).toContainText("VS-CVE-2099-1001");
  await page.waitForTimeout(3000);
  await expect(page.getByTestId("funnel-static")).toBeVisible();
  await expect(page.getByTestId("funnel-3d")).toHaveCount(0);
  expect(scene).toEqual([]);
});

test("sin interacción, la escena 3D llega sola, pero después de cargar la página y los datos", async ({ page }) => {
  const webgl = await page.evaluate(() => {
    const c = document.createElement("canvas");
    return !!(c.getContext("webgl2") ?? c.getContext("webgl"));
  });
  test.skip(!webgl, "este Chromium no tiene WebGL: se ve la versión estática (probada arriba)");
  await page.goto(FORCED);
  // Ni ratón ni teclado: la escena aparece sola, y se monta por fases hasta la última (3).
  await expect(page.getByTestId("funnel-3d")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("funnel-3d")).toHaveAttribute("data-stage", "3", { timeout: 10_000 });
  const order = await page.evaluate(() => {
    const nav = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming;
    const res = performance.getEntriesByType("resource") as PerformanceResourceTiming[];
    const scene = res.find((r) => /FunnelScene/.test(r.name));
    const data = res.filter((r) => r.name.includes("/v1/feed/"));
    return {
      load: nav.loadEventEnd,
      scene: scene?.startTime ?? -1,
      lastData: Math.max(...data.map((r) => r.responseEnd)),
    };
  });
  expect(order.scene).toBeGreaterThan(0);
  expect(order.scene).toBeGreaterThanOrEqual(order.load);
  expect(order.scene).toBeGreaterThanOrEqual(order.lastData);
});

test("con WebGL, la escena 3D se carga aparte y enseña la CVE al pasar el ratón", async ({ page }) => {
  const webgl = await page.evaluate(() => {
    const c = document.createElement("canvas");
    return !!(c.getContext("webgl2") ?? c.getContext("webgl"));
  });
  test.skip(!webgl, "este Chromium no tiene WebGL: se ve la versión estática (probada arriba)");
  await page.goto(FORCED);
  const scene = page.getByTestId("funnel-3d");
  await expect(scene).toBeVisible({ timeout: 15_000 });
  await expect(scene.locator("canvas")).toBeVisible();
  // La etiqueta de cada destino, en HTML bajo el lienzo, lleva la cifra de la API.
  const label = page.getByTestId("funnel").getByTestId("funnel-pad-A");
  await expect(label).toHaveText("A · 1");
  // La alerta de A acaba sobre su plataforma, justo encima de su etiqueta: se busca con el ratón.
  test.setTimeout(120_000);
  await page.waitForTimeout(14_000);
  const pad = (await label.boundingBox())!;
  let seen = "";
  for (let y = pad.y - 90; y < pad.y && !seen; y += 4) {
    for (let x = pad.x - 70; x < pad.x + pad.width + 70 && !seen; x += 4) {
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
