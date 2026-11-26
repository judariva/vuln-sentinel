import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

// Movimiento reducido ANTES de cargar Motion: su preferencia se lee una vez por proceso.
vi.hoisted(() => {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: (query: string) => ({
      matches: query.includes("prefers-reduced-motion"),
      media: query,
      addEventListener() {},
      removeEventListener() {},
      addListener() {},
      removeListener() {},
      onchange: null,
      dispatchEvent: () => false,
    }),
  });
});

// Si alguien intentara cargar la escena 3D con movimiento reducido, el test lo vería.
const sceneLoaded = vi.hoisted(() => ({ value: false }));
vi.mock("@/components/funnel/FunnelScene", () => {
  sceneLoaded.value = true;
  return { default: () => null };
});

const { LiveFunnel } = await import("@/components/funnel/LiveFunnel");
const { NumberTicker } = await import("@/components/magicui/number-ticker");
const { summarizeFunnel } = await import("@/lib/funnel");

describe("prefers-reduced-motion", () => {
  it("el embudo es el SVG estático y la escena 3D no se pide", async () => {
    const data = summarizeFunnel("2099-03-01T18:00:00Z", [], [], true);
    render(<LiveFunnel data={data} />);
    expect(screen.getByTestId("funnel-static")).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 400));
    expect(screen.queryByTestId("funnel-3d")).not.toBeInTheDocument();
    expect(sceneLoaded.value).toBe(false);
  });

  it("los contadores pintan la cifra sin animar", () => {
    render(<NumberTicker value={42} data-testid="kpi" />);
    const visible = screen.getByTestId("kpi").querySelector('[aria-hidden="true"]');
    expect(visible).toHaveTextContent("42");
  });
});
