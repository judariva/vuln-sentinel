import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { App } from "@/App";
import { AlertDetailView } from "@/pages/AlertDetail";
import { MetricsView } from "@/pages/Metrics";
import { CHANGES, LATEST, METRICS, RECORD, fakeFetch } from "./data";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="*" element={<App />} />
      </Routes>
    </MemoryRouter>,
  );
}

const ROUTES = {
  "/v1/feed/alerts/changes": CHANGES,
  "/v1/feed/alerts/latest.json": LATEST,
  "/v1/vulns/VS-CVE-2099-1001.json": RECORD,
  "/v1/metrics/daily.json": METRICS,
};

describe("Hoy", () => {
  it("agrupa las alertas del día por nivel actual y lista los cambios", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(fakeFetch(ROUTES, calls)));
    renderAt("/");
    const a = await screen.findByTestId("level-A");
    expect(within(a).getByText("VS-CVE-2099-1001")).toBeInTheDocument();
    expect(within(a).getByText("sube de nivel")).toBeInTheDocument();
    expect(within(screen.getByTestId("level-B")).getByText("Ninguna hoy.")).toBeInTheDocument();
    const c = screen.getByTestId("level-C");
    expect(within(c).getByText("VS-CVE-2099-1004")).toBeInTheDocument();
    // La alerta de ayer no sale en Hoy.
    expect(screen.queryByText("VS-CVE-2099-0001")).not.toBeInTheDocument();
    // Solo GET a rutas públicas de la API.
    expect(calls.every((u) => u.startsWith("/v1/"))).toBe(true);
  });

  it("si la API falla lo dice y no muestra «sin novedades» (fail-closed)", async () => {
    vi.stubGlobal("fetch", vi.fn(fakeFetch({})));
    renderAt("/");
    expect(await screen.findByRole("alert")).toHaveTextContent("No se pudo leer la API");
    expect(screen.queryByText("Ninguna hoy.")).not.toBeInTheDocument();
  });
});

describe("Detalle de alerta", () => {
  it("muestra productos y rangos, señales, fuentes y la línea de tiempo con las dos marcas", () => {
    render(
      <MemoryRouter>
        <AlertDetailView record={RECORD} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("VS-CVE-2099-1001");
    expect(screen.getByText(">= 1.0.0, < 1.4.2 · >= 1.5.0, < 1.5.3")).toBeInTheDocument();
    const timeline = screen.getByTestId("timeline");
    expect(within(timeline).getByText("Publicado en la fuente")).toBeInTheDocument();
    expect(within(timeline).getByText("Observado")).toBeInTheDocument();
    // La fuente: publicada a las 12:05 y observada a las 13:05.
    const row = within(timeline).getByText("Fuente: cvelistv5").closest("tr")!;
    expect(row).toHaveTextContent("2099-03-01 12:05 UTC");
    expect(row).toHaveTextContent("2099-03-01 13:05 UTC");
    expect(within(timeline).getByText(/Nivel B → A/)).toBeInTheDocument();
  });

  it("nunca pone en un href un enlace que no sea https", () => {
    const { container } = render(
      <MemoryRouter>
        <AlertDetailView record={RECORD} />
      </MemoryRouter>,
    );
    const hrefs = [...container.querySelectorAll("a[href]")].map((a) => a.getAttribute("href")!);
    expect(hrefs.some((h) => h.startsWith("javascript:"))).toBe(false);
    expect(screen.getAllByText("javascript:alert(1)").every((el) => el.tagName !== "A")).toBe(true);
    for (const a of container.querySelectorAll('a[target="_blank"]')) {
      expect(a.getAttribute("rel")).toContain("noopener");
    }
  });

  it("pide el registro a la API con el id de la ruta", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(fakeFetch(ROUTES, calls)));
    renderAt("/alertas/VS-CVE-2099-1001");
    expect(await screen.findByText("Productos y rangos")).toBeInTheDocument();
    expect(calls).toEqual(["/v1/vulns/VS-CVE-2099-1001.json"]);
  });

  it("un id mal formado no llega a la API", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(fakeFetch(ROUTES, calls)));
    renderAt("/alertas/..%2F..%2Fadmin");
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(calls).toEqual([]);
  });
});

describe("Métricas", () => {
  it("pinta embudo, detección, ventaja sobre KEV y tipos", () => {
    render(<MetricsView doc={METRICS} />);
    for (const t of ["Embudo", "Tiempo de detección", "Ventaja sobre KEV", "Tipos de cambio"]) {
      expect(screen.getByRole("heading", { name: t })).toBeInTheDocument();
    }
    // Embudo: 1100 ingeridas (es-ES no agrupa los números de 4 cifras) y 3 alertas.
    expect(screen.getByText("1100")).toBeInTheDocument();
    // Detección del último día con datos (35, no 99).
    expect(screen.getByText("35")).toBeInTheDocument();
    expect(screen.queryByText("99")).not.toBeInTheDocument();
  });
});

describe("Pantallas restringidas", () => {
  it.each([
    ["/fuentes", "Fuentes"],
    ["/admin", "Administración"],
  ])("%s se marca como «detrás de Access» y no llama a la API", (path, title) => {
    const fetchSpy = vi.fn(fakeFetch({}));
    vi.stubGlobal("fetch", fetchSpy);
    renderAt(path);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(title);
    expect(screen.getByTestId("access-notice")).toHaveTextContent("Detrás de Access");
    expect(screen.getByTestId("access-notice")).toHaveTextContent("datos de ejemplo");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("Fuentes muestra UNKNOWN para una fuente caída", () => {
    renderAt("/fuentes");
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
  });
});

describe("Tema", () => {
  it("oscuro por defecto y cambia a claro", async () => {
    vi.stubGlobal("fetch", vi.fn(fakeFetch(ROUTES)));
    document.documentElement.classList.add("dark");
    window.localStorage.clear();
    renderAt("/fuentes");
    const btn = screen.getByRole("button", { name: "Cambiar a tema claro" });
    await userEvent.click(btn);
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(window.localStorage.getItem("vs-theme")).toBe("light");
    await userEvent.click(screen.getByRole("button", { name: "Cambiar a tema oscuro" }));
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });
});
