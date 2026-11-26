import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { alertsPerDay, detection, funnel } from "@/api/metrics";
import { getAllChanges } from "@/api/client";
import { LevelBadge } from "@/components/LevelBadge";
import { ConfigError, readConfig } from "@/config";
import { safeUrl, utc } from "@/lib/format";
import { describeEvents } from "@/lib/timeline";
import { summarizeToday } from "@/lib/today";
import { DEFAULT_THEME, levelClass, levelColor, storedTheme } from "@/theme/tokens";
import { CHANGES, LATEST, METRICS } from "./data";

const SRC = path.resolve(import.meta.dirname, "..");

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = path.join(dir, name);
    return statSync(p).isDirectory() ? files(p) : [p];
  });
}

describe("configuración (ADR-0016)", () => {
  it("la URL base y la marca salen de VITE_*", () => {
    const cfg = readConfig({ VITE_API_BASE_URL: "https://api.example.invalid/", VITE_BRAND_NAME: "Marca" });
    expect(cfg).toEqual({ apiBaseUrl: "https://api.example.invalid", brandName: "Marca" });
  });

  it("sin variables: mismo origen y rótulo genérico", () => {
    expect(readConfig({})).toEqual({ apiBaseUrl: "", brandName: "Monitor de vulnerabilidades" });
  });

  it("rechaza http fuera de local y URL rotas", () => {
    expect(() => readConfig({ VITE_API_BASE_URL: "http://api.example.invalid" })).toThrow(ConfigError);
    expect(() => readConfig({ VITE_API_BASE_URL: "no es url" })).toThrow(ConfigError);
    expect(readConfig({ VITE_API_BASE_URL: "http://127.0.0.1:8787" }).apiBaseUrl).toBe("http://127.0.0.1:8787");
  });

  it("ningún fichero del portal escribe un host: solo URL ficticias en los tests", () => {
    const offenders = files(SRC)
      .filter((f) => /\.(ts|tsx|css)$/.test(f) && !/\.test\.tsx?$/.test(f) && !f.includes(`${path.sep}test${path.sep}`))
      .filter((f) => /https?:\/\/(?!127\.0\.0\.1|localhost)[a-z0-9.-]+\.[a-z]{2,}/i.test(readFileSync(f, "utf8")));
    expect(offenders).toEqual([]);
  });
});

describe("tokens: un solo sistema visual", () => {
  it("los colores solo se escriben en tokens.css (fuera de los componentes generados por shadcn)", () => {
    const color = /#[0-9a-f]{3,8}\b|\boklch\(|\brgba?\(|\bhsla?\(/i;
    const offenders = files(SRC)
      .filter((f) => /\.(ts|tsx|css)$/.test(f))
      .filter((f) => !f.endsWith(path.join("theme", "tokens.css")))
      .filter((f) => !f.includes(path.join("components", "ui")))
      .filter((f) => !f.includes(`${path.sep}test${path.sep}`))
      .filter((f) => color.test(readFileSync(f, "utf8")));
    expect(offenders).toEqual([]);
  });

  it("A, B y C tienen su variable en tokens.css, una sola vez", () => {
    const css = readFileSync(path.join(SRC, "theme", "tokens.css"), "utf8");
    for (const lv of ["a", "b", "c"]) {
      expect(css.match(new RegExp(`--level-${lv}:`, "g"))).toHaveLength(1);
    }
  });

  it("una sola familia tipográfica", () => {
    const css = readFileSync(path.join(SRC, "theme", "tokens.css"), "utf8");
    expect(css.match(/--font-family:/g)).toHaveLength(1);
    const elsewhere = files(SRC)
      .filter((f) => /\.(ts|tsx|css)$/.test(f) && !f.endsWith("tokens.css") && !f.includes(`${path.sep}test${path.sep}`))
      .filter((f) => /font-family\s*:/.test(readFileSync(f, "utf8")));
    expect(elsewhere).toEqual([]);
  });

  it("la insignia usa el color del nivel", () => {
    render(<LevelBadge level="B" />);
    const badge = screen.getByLabelText(/Nivel B/);
    for (const cls of levelClass.B.split(" ")) expect(badge).toHaveClass(cls);
    expect(levelColor.B).toBe("var(--level-b)");
  });

  it("tema oscuro por defecto", () => {
    expect(DEFAULT_THEME).toBe("dark");
    expect(storedTheme({ getItem: () => null })).toBe("dark");
    expect(storedTheme({ getItem: () => "light" })).toBe("light");
    expect(storedTheme({ getItem: () => "rosa" })).toBe("dark");
  });
});

describe("lógica", () => {
  it("safeUrl solo deja https", () => {
    expect(safeUrl("https://a.example.invalid/x")).toBe("https://a.example.invalid/x");
    for (const bad of ["javascript:alert(1)", "data:text/html,x", "http://a.example.invalid", "//x", "", null]) {
      expect(safeUrl(bad)).toBeNull();
    }
  });

  it("utc formatea en UTC y no inventa fechas", () => {
    expect(utc("2099-03-01T13:05:00Z")).toBe("2099-03-01 13:05 UTC");
    expect(utc(null)).toBe("—");
    expect(utc("basura")).toBe("—");
  });

  it("describeEvents convierte eventos OSV", () => {
    expect(describeEvents([{ introduced: "0" }, { fixed: "3.1" }])).toBe("< 3.1");
    expect(describeEvents([{ introduced: "2.0" }])).toBe(">= 2.0");
    expect(describeEvents([{ introduced: "1.0" }, { last_affected: "1.2" }])).toBe(">= 1.0, <= 1.2");
  });

  it("summarizeToday usa el nivel actual y solo el día de generated_at", () => {
    const s = summarizeToday(CHANGES.generated_at, CHANGES.entries, LATEST.alerts);
    expect(s.day).toBe("2099-03-01");
    expect(s.byLevel.A.map((a) => a.id)).toEqual(["VS-CVE-2099-1001"]);
    expect(s.byLevel.A[0].types).toEqual(["new", "level_up"]);
    expect(s.byLevel.B).toEqual([]);
    expect(s.byLevel.C.map((a) => a.id)).toEqual(["VS-CVE-2099-1004"]);
    expect(s.changes).toHaveLength(4);
  });

  it("métricas: embudo, alertas por día y detección del último día", () => {
    expect(funnel(METRICS.rows).map((s) => s.value)).toEqual([1100, 70, 8, 3]);
    expect(alertsPerDay(METRICS.rows)).toEqual([{ day: "2099-02-28", A: 1, B: 0, C: 2 }]);
    const det = detection(METRICS.rows);
    expect(det.day).toBe("2099-02-28");
    expect(det.byLevel[0]).toEqual({ level: "A", p50: 35, p95: 140 });
  });

  it("getAllChanges sigue el cursor hasta el final", async () => {
    const pages = [
      { ...CHANGES, entries: CHANGES.entries.slice(0, 2), next: "c1", has_more: true },
      { ...CHANGES, entries: CHANGES.entries.slice(2), next: "c2", has_more: false },
    ];
    const seen: string[] = [];
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      seen.push(String(input));
      return new Response(JSON.stringify(pages[seen.length - 1]), { status: 200 });
    });
    const out = await getAllChanges("alerts");
    expect(out.entries).toHaveLength(CHANGES.entries.length);
    expect(seen).toEqual(["/v1/feed/alerts/changes", "/v1/feed/alerts/changes?since=c1"]);
  });
});
