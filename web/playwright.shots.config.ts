import base from "./playwright.config";
import { defineConfig } from "@playwright/test";

// Capturas (T8b; T8c): las mismas pantallas que la prueba de humo, sin aserciones de humo, con su
// propio servidor y el fixture de VOLUMEN (`--volume 240`: ~245 CVE sintéticas con cambios en el
// día y unas pocas A/B/C), para que el embudo se vea con un día realista. Los tests siguen con el
// montaje base. Salida en `VS_SHOTS_DIR` o, por defecto, en `local/tmp/shots` (ignorado por git).
const PORT = Number(process.env.VS_SHOTS_PORT ?? 8789);
const BASE = `http://127.0.0.1:${PORT}`;

export default defineConfig({
  ...base,
  testMatch: "shots.spec.ts",
  testIgnore: [],
  use: { ...base.use, baseURL: BASE },
  webServer: {
    command: `uv run python -m tests.portal_fixture --port ${PORT} --static web/dist --volume 240`,
    cwd: "..",
    url: `${BASE}/v1/feed/alerts/latest.json`,
    reuseExistingServer: false,
    timeout: 120_000,
    stdout: "ignore",
    stderr: "pipe",
  },
});
