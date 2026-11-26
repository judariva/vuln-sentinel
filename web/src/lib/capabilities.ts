/** Qué puede pintar el navegador. La escena 3D solo se intenta si hay WebGL y nadie pidió menos movimiento. */

export function prefersReducedMotion(win: Pick<Window, "matchMedia"> | undefined = globalThis.window): boolean {
  try {
    return !!win?.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
}

/**
 * Qué WebGL hay (T8d):
 * - `none`: no hay contexto;
 * - `software`: lo pinta la CPU (SwiftShader, llvmpipe, «Microsoft Basic Render»…) o el navegador
 *   avisa de que irá lento (`failIfMajorPerformanceCaveat`). En esa máquina la escena iría a tirones
 *   también para una persona: se queda el SVG;
 * - `hardware`: GPU. Solo entonces se carga la escena.
 */
export type WebGLTier = "none" | "software" | "hardware";

/** Nombres de renderizador por software (cadena de `WEBGL_debug_renderer_info` o `RENDERER`). */
export const SOFTWARE_RENDERER = /swiftshader|llvmpipe|softpipe|software|microsoft basic render/i;

type GL = WebGLRenderingContext | WebGL2RenderingContext;

function context(doc: Document, attrs?: WebGLContextAttributes): GL | null {
  const canvas = doc.createElement("canvas");
  return (
    (canvas.getContext("webgl2", attrs) as WebGL2RenderingContext | null) ??
    (canvas.getContext("webgl", attrs) as WebGLRenderingContext | null)
  );
}

/** Se suelta el contexto de prueba: el navegador limita cuántos hay a la vez. */
function release(gl: GL | null) {
  gl?.getExtension("WEBGL_lose_context")?.loseContext();
}

function rendererName(gl: GL): string {
  const info = gl.getExtension("WEBGL_debug_renderer_info");
  const name = info ? gl.getParameter(info.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
  return String(name ?? "");
}

export function webglTier(doc: Document | undefined = globalThis.document): WebGLTier {
  if (!doc) return "none";
  try {
    const strict = context(doc, { failIfMajorPerformanceCaveat: true });
    if (!strict) {
      // Con el aviso de rendimiento no sale: ¿hay WebGL lento o no hay nada?
      const any = context(doc);
      release(any);
      return any ? "software" : "none";
    }
    const name = rendererName(strict);
    release(strict);
    return SOFTWARE_RENDERER.test(name) ? "software" : "hardware";
  } catch {
    return "none";
  }
}

export function canUseWebGL(doc: Document | undefined = globalThis.document): boolean {
  return webglTier(doc) !== "none";
}

/**
 * Parámetro de prueba, sin enlace en ningún sitio: `?escena=forzar` carga la escena aunque el WebGL
 * sea por software. Solo sirve para medirla en CI (Lighthouse, Playwright), que no tiene GPU.
 */
export const FORCE_SCENE_PARAM = "escena";
export const FORCE_SCENE_VALUE = "forzar";

export function sceneForced(loc: Pick<Location, "search"> | undefined = globalThis.location): boolean {
  try {
    return new URLSearchParams(loc?.search ?? "").get(FORCE_SCENE_PARAM) === FORCE_SCENE_VALUE;
  } catch {
    return false;
  }
}

/** ¿Se carga la escena? Con GPU, sí; con WebGL por software, solo si se fuerza; sin WebGL, nunca. */
export function shouldLoadScene(tier: WebGLTier, forced: boolean): boolean {
  return tier === "hardware" || (tier === "software" && forced);
}

/**
 * Escena ligera: pantalla pequeña o CPU con pocos núcleos (≤ 4). Menos partículas y menos
 * segmentos por esfera. El ritmo (30 fps) es el mismo para todos.
 */
export function liteScene(
  win: { innerWidth?: number; navigator?: { hardwareConcurrency?: number } } | undefined = globalThis.window,
): boolean {
  const width = win?.innerWidth ?? Infinity;
  const cores = win?.navigator?.hardwareConcurrency ?? Infinity;
  return width < 768 || cores <= 4;
}

/** Cede el hilo principal entre dos trozos de trabajo (`scheduler.yield` o, si no hay, un `setTimeout`). */
export function yieldToMain(): Promise<void> {
  const s = (globalThis as { scheduler?: { yield?: () => Promise<void> } }).scheduler;
  if (s?.yield) return s.yield();
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/**
 * Ejecuta `fn` cuando el navegador esté libre (tras pintar los datos). Devuelve la cancelación.
 * Sin `requestIdleCallback` (Safari), con un `setTimeout`.
 */
export function whenIdle(fn: () => void, timeout = 2000): () => void {
  const w = globalThis as typeof globalThis & {
    requestIdleCallback?: (cb: () => void, opts?: { timeout: number }) => number;
    cancelIdleCallback?: (id: number) => void;
  };
  if (w.requestIdleCallback && w.cancelIdleCallback) {
    const id = w.requestIdleCallback(fn, { timeout });
    return () => w.cancelIdleCallback?.(id);
  }
  const id = setTimeout(fn, 200);
  return () => clearTimeout(id);
}

/**
 * Ejecuta `fn` (una vez) cuando la página ya cargó (`load`), se pintó (dos fotogramas) y el
 * navegador queda libre (`whenIdle`). Es el momento de la escena 3D (T8c, ADR-0024): viva al
 * llegar, sin esperar a que nadie interactúe, pero nunca antes que los datos. Devuelve la
 * cancelación.
 */
export function afterLoadIdle(fn: () => void, doc: Document = document, win: Window = window): () => void {
  let cancelled = false;
  let cancelIdle: (() => void) | undefined;
  let raf = 0;
  const go = () => {
    if (cancelled) return;
    raf = win.requestAnimationFrame(() => {
      raf = win.requestAnimationFrame(() => {
        raf = 0;
        if (!cancelled) cancelIdle = whenIdle(fn);
      });
    });
  };
  if (doc.readyState === "complete") go();
  else win.addEventListener("load", go, { once: true });
  return () => {
    cancelled = true;
    win.removeEventListener("load", go);
    if (raf) win.cancelAnimationFrame(raf);
    cancelIdle?.();
  };
}
