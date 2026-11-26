import { describe, expect, it } from "vitest";
import { collidesWithApi, PATHS } from "@/routes";

describe("rutas del portal", () => {
  it.each(Object.entries(PATHS))("%s (%s) no invade ningún prefijo de la API", (_name, path) => {
    expect(collidesWithApi(path)).toBe(false);
  });

  it("detecta la colisión que rompía Administración en el mismo origen", () => {
    expect(collidesWithApi("/admin")).toBe(true);
    expect(collidesWithApi("/administracion")).toBe(true);
    expect(collidesWithApi("/v1/feed")).toBe(true);
  });
});
