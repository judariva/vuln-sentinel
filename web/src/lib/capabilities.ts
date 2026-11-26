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

const INTERACTION = ["pointermove", "pointerdown", "keydown", "wheel", "touchstart", "scroll"] as const;

/**
 * Ejecuta `fn` (una vez) cuando la persona haga algo en la página: mover el ratón, tocar, una tecla
 * o desplazarse. Devuelve la cancelación.
 */
export function onFirstInteraction(fn: () => void, target: Pick<Window, "addEventListener" | "removeEventListener"> = window): () => void {
  let done = false;
  const handler = () => {
    if (done) return;
    done = true;
    off();
    fn();
  };
  const off = () => INTERACTION.forEach((t) => target.removeEventListener(t, handler));
  INTERACTION.forEach((t) => target.addEventListener(t, handler, { passive: true }));
  return off;
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
