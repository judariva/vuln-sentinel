import base from "./playwright.config";
import { defineConfig } from "@playwright/test";

// Capturas (T8b): las mismas pantallas y el mismo servidor que la prueba de humo, sin aserciones de
// humo. Salida en `VS_SHOTS_DIR` o, por defecto, en `local/tmp/shots` (ignorado por git).
export default defineConfig({
  ...base,
  testMatch: "shots.spec.ts",
  testIgnore: [],
});
