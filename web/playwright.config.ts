import { defineConfig, devices } from "@playwright/test";

// Prueba de humo: la API de T6 con fixtures (`tests/portal_fixture.py`, vía `uv run`) sirve en el
// mismo origen el build del portal (`web/dist`). Solo 127.0.0.1: nada sale a la red.
const PORT = Number(process.env.VS_SMOKE_PORT ?? 8787);
const BASE = `http://127.0.0.1:${PORT}`;

export default defineConfig({
  testDir: "./e2e",
  // Las capturas tienen su propia configuración (`playwright.shots.config.ts`).
  testIgnore: "shots.spec.ts",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: BASE,
    trace: "off",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `uv run python -m tests.portal_fixture --port ${PORT} --static web/dist`,
    cwd: "..",
    url: `${BASE}/v1/feed/alerts/latest.json`,
    reuseExistingServer: false,
    timeout: 120_000,
    stdout: "ignore",
    stderr: "pipe",
  },
});
