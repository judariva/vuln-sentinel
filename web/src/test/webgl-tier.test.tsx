import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  liteScene,
  sceneForced,
  shouldLoadScene,
  SOFTWARE_RENDERER,
  webglTier,
} from "@/lib/capabilities";
import { LiveFunnel } from "@/components/funnel/LiveFunnel";
import { limitParticles, MAX_PARTICLES_LITE, summarizeFunnel, type FunnelParticle } from "@/lib/funnel";

/**
 * T8d: con WebGL por software (sin GPU) se queda el SVG; la escena solo se carga con GPU o si se
 * fuerza con el parámetro de prueba. Y la escena ligera recorta partículas sin tocar las alertas.
 */

const sceneLoaded = vi.hoisted(() => ({ value: false }));
vi.mock("@/components/funnel/FunnelScene", () => {
  sceneLoaded.value = true;
  return { default: () => <div data-testid="funnel-3d" /> };
});

const DEBUG_RENDERER = 0x9246;

/** Contexto WebGL falso: nombre de renderizador y si sale con `failIfMajorPerformanceCaveat`. */
function fakeGL(renderer: string, lost: { n: number }) {
  return {
    RENDERER: 0x1f01,
    getExtension: (name: string) =>
      name === "WEBGL_debug_renderer_info"
        ? { UNMASKED_RENDERER_WEBGL: DEBUG_RENDERER }
        : name === "WEBGL_lose_context"
          ? { loseContext: () => (lost.n += 1) }
          : null,
    getParameter: (p: number) => (p === DEBUG_RENDERER ? renderer : "WebKit WebGL"),
  };
}

function fakeDoc(opts: { renderer?: string; caveat?: boolean; none?: boolean }) {
  const lost = { n: 0 };
  const doc = {
    createElement: () => ({
      getContext: (_type: string, attrs?: WebGLContextAttributes) => {
        if (opts.none) return null;
        if (opts.caveat && attrs?.failIfMajorPerformanceCaveat) return null;
        return fakeGL(opts.renderer ?? "ANGLE (NVIDIA GeForce)", lost);
      },
    }),
  } as unknown as Document;
  return { doc, lost };
}

describe("nivel de WebGL", () => {
  it("con GPU es hardware y se suelta el contexto de prueba", () => {
    const { doc, lost } = fakeDoc({ renderer: "ANGLE (Intel, Intel(R) UHD Graphics 620, D3D11)" });
    expect(webglTier(doc)).toBe("hardware");
    expect(lost.n).toBe(1);
  });

  it.each([
    "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)",
    "Google SwiftShader",
    "llvmpipe (LLVM 15.0.7, 256 bits)",
    "Mesa softpipe",
    "Microsoft Basic Render Driver",
    "Software Rasterizer",
  ])("por software: %s", (renderer) => {
    expect(SOFTWARE_RENDERER.test(renderer)).toBe(true);
    expect(webglTier(fakeDoc({ renderer }).doc)).toBe("software");
  });

  it("si solo sale sin `failIfMajorPerformanceCaveat`, es software", () => {
    const { doc, lost } = fakeDoc({ caveat: true });
    expect(webglTier(doc)).toBe("software");
    expect(lost.n).toBe(1);
  });

  it("sin contexto o sin documento, none", () => {
    expect(webglTier(fakeDoc({ none: true }).doc)).toBe("none");
    expect(webglTier(undefined)).toBe("none");
  });

  it("la escena se carga con GPU; con software, solo forzada; sin WebGL, nunca", () => {
    expect(shouldLoadScene("hardware", false)).toBe(true);
    expect(shouldLoadScene("software", false)).toBe(false);
    expect(shouldLoadScene("software", true)).toBe(true);
    expect(shouldLoadScene("none", true)).toBe(false);
  });

  it("el parámetro de prueba es exacto", () => {
    expect(sceneForced({ search: "?escena=forzar" })).toBe(true);
    expect(sceneForced({ search: "?x=1&escena=forzar" })).toBe(true);
    expect(sceneForced({ search: "?escena=1" })).toBe(false);
    expect(sceneForced({ search: "" })).toBe(false);
    expect(sceneForced(undefined)).toBe(false);
  });
});

describe("escena ligera", () => {
  it("pantalla pequeña o ≤ 4 núcleos", () => {
    expect(liteScene({ innerWidth: 390, navigator: { hardwareConcurrency: 8 } })).toBe(true);
    expect(liteScene({ innerWidth: 1280, navigator: { hardwareConcurrency: 4 } })).toBe(true);
    expect(liteScene({ innerWidth: 1280, navigator: { hardwareConcurrency: 8 } })).toBe(false);
    expect(liteScene({ innerWidth: 1280, navigator: {} })).toBe(false);
  });

  it("recorta CVE sin nivel, nunca alertas", () => {
    const none: FunnelParticle[] = Array.from({ length: 400 }, (_, i) => ({ id: `N-${i}`, level: "none" }));
    const alerts: FunnelParticle[] = [
      { id: "A-1", level: "A" },
      { id: "B-1", level: "B" },
      { id: "C-1", level: "C" },
    ];
    const out = limitParticles([...none, ...alerts], MAX_PARTICLES_LITE);
    expect(out).toHaveLength(MAX_PARTICLES_LITE);
    expect(out.slice(0, 3).map((p) => p.id)).toEqual(["A-1", "B-1", "C-1"]);
    // Con más alertas que el tope, se quedan todas.
    const many = Array.from({ length: 5 }, (_, i) => ({ id: `A-${i}`, level: "A" as const }));
    expect(limitParticles(many, 2)).toHaveLength(5);
  });
});

describe("LiveFunnel según el WebGL", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    window.history.replaceState({}, "", "/");
  });

  function stubCanvas(renderer: string) {
    const lost = { n: 0 };
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockImplementation(
      // jsdom no tiene WebGL: se le da uno falso con el renderizador que toque.
      ((type: string) => (type.startsWith("webgl") ? fakeGL(renderer, lost) : null)) as never,
    );
  }

  const data = summarizeFunnel("2099-03-01T18:00:00Z", [], [], true);
  const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

  it("con SwiftShader se queda el SVG y el bloque 3D no se pide", async () => {
    stubCanvas("ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)");
    render(<LiveFunnel data={data} />);
    await wait(800);
    expect(screen.getByTestId("funnel-static")).toBeInTheDocument();
    expect(screen.queryByTestId("funnel-3d")).not.toBeInTheDocument();
    expect(sceneLoaded.value).toBe(false);
  });

  it("con SwiftShader y `?escena=forzar`, se carga (solo para medir)", async () => {
    stubCanvas("Google SwiftShader");
    window.history.replaceState({}, "", "/?escena=forzar");
    render(<LiveFunnel data={data} />);
    expect(await screen.findByTestId("funnel-3d", {}, { timeout: 3000 })).toBeInTheDocument();
    expect(sceneLoaded.value).toBe(true);
  });

  it("con GPU, se carga sola", async () => {
    stubCanvas("ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, D3D11)");
    render(<LiveFunnel data={data} />);
    expect(await screen.findByTestId("funnel-3d", {}, { timeout: 3000 })).toBeInTheDocument();
  });
});
