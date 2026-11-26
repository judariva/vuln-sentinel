/** Qué puede pintar el navegador. La escena 3D solo se intenta si hay WebGL y nadie pidió menos movimiento. */

export function prefersReducedMotion(win: Pick<Window, "matchMedia"> | undefined = globalThis.window): boolean {
  try {
    return !!win?.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
}

export function canUseWebGL(doc: Document | undefined = globalThis.document): boolean {
  try {
    const canvas = doc?.createElement("canvas");
    const gl = canvas?.getContext("webgl2") ?? canvas?.getContext("webgl");
    // Se suelta el contexto de prueba: el navegador limita cuántos hay a la vez.
    gl?.getExtension("WEBGL_lose_context")?.loseContext();
    return !!gl;
  } catch {
    return false;
  }
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
