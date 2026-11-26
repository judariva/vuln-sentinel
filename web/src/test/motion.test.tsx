import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it, vi } from "vitest";
import type { ChangeEntry, ChangesPage } from "@/api/types";
import { App } from "@/App";
import { getAllChanges } from "@/api/client";
import { FunnelStatic, MAX_STATIC_DOTS } from "@/components/funnel/FunnelStatic";
import { funnelLabel } from "@/components/funnel/geometry";
import { LevelBadge } from "@/components/LevelBadge";
import { NumberTicker } from "@/components/magicui/number-ticker";
import { SourceBeams } from "@/components/SourceBeams";
import { SOURCES } from "@/fixtures/restricted";
import { canUseWebGL, prefersReducedMotion } from "@/lib/capabilities";
import { alertCount, MAX_PARTICLES, summarizeFunnel, unitHash } from "@/lib/funnel";
import { CHANGES, DAY, LATEST, fakeFetch } from "./data";

const sha = "f".repeat(64);
const entry = (id: string, modified: string, level: ChangeEntry["level"], type = "new"): ChangeEntry => ({
  id,
  modified,
  level,
  type,
  sha256: sha,
});

/** Feed completo de prueba: 2 CVE sin nivel hoy, la de A (con dos cambios), la de C y una de ayer. */
const ALL: ChangesPage = {
  ...CHANGES,
  feed: "all",
  entries: [
    entry("VS-CVE-2099-0001", "2099-02-28T23:00:00Z", "C"),
    entry("VS-CVE-2099-1001", `${DAY}T13:05:00Z`, "C"),
    entry("VS-CVE-2099-1001", `${DAY}T16:05:00Z`, "A", "level_up"),
    entry("VS-CVE-2099-1002", `${DAY}T13:05:00Z`, "none"),
    entry("VS-CVE-2099-1003", `${DAY}T13:06:00Z`, "none"),
    entry("VS-CVE-2099-1004", `${DAY}T13:05:00Z`, "C"),
  ],
};

describe("embudo: las cifras salen de la API", () => {
  it("cuenta CVE distintas del día con su nivel actual", () => {
    const f = summarizeFunnel(ALL.generated_at, ALL.entries, LATEST.alerts, true);
    expect(f.day).toBe(DAY);
    expect(f.total).toBe(4);
    expect(f.counts).toEqual({ A: 1, B: 0, C: 1, none: 2 });
    expect(alertCount(f)).toBe(2);
    expect(f.particles.map((p) => p.id)).toEqual(["VS-CVE-2099-1001", "VS-CVE-2099-1004", "VS-CVE-2099-1002", "VS-CVE-2099-1003"]);
    expect(f.complete).toBe(true);
  });

  it("si hay que recortar, se dibujan siempre todas las alertas y el total no cambia", () => {
    const many = Array.from({ length: 50 }, (_, i) => entry(`VS-CVE-2099-${5000 + i}`, `${DAY}T10:00:00Z`, "none"));
    const f = summarizeFunnel(ALL.generated_at, [...ALL.entries, ...many], LATEST.alerts, true, 10);
    expect(f.total).toBe(54);
    expect(f.particles).toHaveLength(10);
    expect(f.particles.filter((p) => p.level !== "none").map((p) => p.id)).toEqual(["VS-CVE-2099-1001", "VS-CVE-2099-1004"]);
    expect(MAX_PARTICLES).toBeGreaterThan(1000);
  });

  it("el texto accesible dice «al menos» si el feed no se leyó entero", () => {
    const f = summarizeFunnel(ALL.generated_at, ALL.entries, LATEST.alerts, false);
    expect(funnelLabel(f)).toContain("al menos 4 CVE");
    expect(funnelLabel(f)).toContain("A: 1, B: 0, C: 1");
  });

  it("getAllChanges marca `complete` falso si quedan páginas", async () => {
    const page: ChangesPage = { ...ALL, entries: [], has_more: true, next: "cursor" };
    vi.stubGlobal("fetch", vi.fn(fakeFetch({ "/v1/feed/all/changes": page })));
    const r = await getAllChanges("all");
    expect(r.complete).toBe(false);
    vi.stubGlobal("fetch", vi.fn(fakeFetch({ "/v1/feed/all/changes": ALL })));
    expect((await getAllChanges("all")).complete).toBe(true);
  });

  it("las posiciones son deterministas (hash del id), no azar", () => {
    expect(unitHash("VS-CVE-2099-1001", 1)).toBe(unitHash("VS-CVE-2099-1001", 1));
    expect(unitHash("VS-CVE-2099-1001", 1)).not.toBe(unitHash("VS-CVE-2099-1001", 2));
    for (const s of [0, 1, 7]) {
      const v = unitHash("x", s);
      expect(v >= 0 && v < 1).toBe(true);
    }
  });
});

describe("embudo estático (SVG)", () => {
  it("cada alerta es un punto con su CVE y el color de su nivel; las demás, con tope", () => {
    const many = Array.from({ length: MAX_STATIC_DOTS + 30 }, (_, i) => entry(`VS-CVE-2099-${6000 + i}`, `${DAY}T10:00:00Z`, "none"));
    const f = summarizeFunnel(ALL.generated_at, [...ALL.entries, ...many], LATEST.alerts, true);
    const { container } = render(<FunnelStatic data={f} />);
    const svg = screen.getByTestId("funnel-static");
    expect(svg).toHaveAttribute("role", "img");
    expect(svg.getAttribute("aria-label")).toBe(funnelLabel(f));
    const titles = [...container.querySelectorAll("circle > title")].map((t) => t.textContent);
    expect(titles).toContain("VS-CVE-2099-1001 · Nivel A · explotación activa");
    expect(titles).toContain("VS-CVE-2099-1004 · Nivel C · RCE sin exploit");
    expect(titles).toHaveLength(MAX_STATIC_DOTS + 2);
    const a = [...container.querySelectorAll("circle")].find((c) => c.textContent?.startsWith("VS-CVE-2099-1001"));
    expect(a?.getAttribute("style")).toContain("var(--level-a)");
  });
});

describe("contadores de KPI", () => {
  it("la cifra real está en el DOM desde el principio (lectores de pantalla y data-value)", () => {
    render(<NumberTicker value={1234} data-testid="kpi" />);
    const kpi = screen.getByTestId("kpi");
    expect(kpi).toHaveAttribute("data-value", "1234");
    expect(within(kpi).getByText("1234")).toHaveClass("sr-only");
  });
});

describe("Hoy con el embudo", () => {
  const ROUTES = {
    "/v1/feed/alerts/changes": CHANGES,
    "/v1/feed/alerts/latest.json": LATEST,
    "/v1/feed/all/changes": ALL,
  };

  it("el embudo pinta las cifras del feed completo y, sin WebGL, la versión estática", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(fakeFetch(ROUTES, calls)));
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route path="*" element={<App />} />
        </Routes>
      </MemoryRouter>,
    );
    const funnel = await screen.findByTestId("funnel");
    await waitFor(() => expect(funnel).toHaveAttribute("data-total", "4"));
    expect(funnel).toHaveAttribute("data-complete", "true");
    expect(within(funnel).getByTestId("funnel-static")).toBeInTheDocument();
    expect(within(screen.getByTestId("level-A")).getByText("VS-CVE-2099-1001")).toBeInTheDocument();
    expect(calls.every((u) => u.startsWith("/v1/"))).toBe(true);
  });

  it("si falla el feed completo, solo falla el embudo: las alertas se ven", async () => {
    const { "/v1/feed/all/changes": _ignored, ...rest } = ROUTES;
    void _ignored;
    vi.stubGlobal("fetch", vi.fn(fakeFetch(rest)));
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route path="*" element={<App />} />
        </Routes>
      </MemoryRouter>,
    );
    const funnel = await screen.findByTestId("funnel");
    expect(await within(funnel).findByRole("alert")).toHaveTextContent("No se pudo leer la API");
    expect(within(screen.getByTestId("level-A")).getByText("VS-CVE-2099-1001")).toBeInTheDocument();
    expect(within(screen.getByTestId("level-C")).getByText("VS-CVE-2099-1004")).toBeInTheDocument();
  });
});

describe("haces de Fuentes", () => {
  it("una fuente en UNKNOWN sale cortada, y el texto accesible lo dice", () => {
    render(<SourceBeams sources={SOURCES} />);
    const beams = screen.getByTestId("source-beams");
    expect(beams.getAttribute("aria-label")).toContain("1 en UNKNOWN");
    expect(beams.getAttribute("aria-label")).toContain("exploits UNKNOWN");
    expect(beams.querySelector('[data-status="unknown"]')).toHaveTextContent("exploits");
  });
});

describe("cambio de nivel", () => {
  it("la insignia sigue al nivel nuevo", () => {
    const { rerender } = render(<LevelBadge level="B" />);
    expect(screen.getByLabelText(/Nivel B/)).toHaveAttribute("data-level", "B");
    rerender(<LevelBadge level="A" />);
    expect(screen.getByLabelText(/Nivel A/)).toHaveAttribute("data-level", "A");
  });
});

describe("capacidades", () => {
  it("sin matchMedia no se asume movimiento reducido; sin WebGL no hay 3D", () => {
    expect(prefersReducedMotion(undefined)).toBe(false);
    expect(prefersReducedMotion({ matchMedia: () => ({ matches: true }) as MediaQueryList })).toBe(true);
    const doc = { createElement: () => ({ getContext: () => null }) } as unknown as Document;
    expect(canUseWebGL(doc)).toBe(false);
  });
});
