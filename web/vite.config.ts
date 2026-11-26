/// <reference types="vitest/config" />
import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Hosts, marca y URL base: solo variables VITE_* (ADR-0016). Ver `.env.example`.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  build: {
    sourcemap: false,
    // El manifiesto dice qué bloques carga la página al empezar y cuáles son de la escena 3D:
    // lo lee `scripts/check-budgets.mjs` (presupuestos en gzip, T8b).
    manifest: true,
    // El aviso de Vite (500 kB sin comprimir) no es el criterio: los presupuestos en gzip sí.
    chunkSizeWarningLimit: 1200,
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    css: false,
  },
});
