import { useReducedMotion } from "motion/react";
import { Component, lazy, Suspense, useEffect, useState, type ReactNode } from "react";
import { FunnelStatic } from "@/components/funnel/FunnelStatic";
import { canUseWebGL, onFirstInteraction, whenIdle } from "@/lib/capabilities";
import type { FunnelData } from "@/lib/funnel";

/**
 * Elige entre la escena 3D y el SVG estático. Robustez (T8b, ADR-0024):
 * - la escena es otro bloque (`lazy`, ~250 KB gzip) y se pide tras la primera interacción con la
 *   página (ratón, tecla, toque, desplazamiento) y cuando el navegador queda libre. Medido con CPU
 *   ×4: evaluar three.js y montar la escena son ~1,7 s de hilo principal; si entra sola al cargar,
 *   compite con los datos. Mientras llega, y si falla, se ve el SVG con las mismas cifras;
 * - con `prefers-reduced-motion` o sin WebGL nunca se pide.
 */
const FunnelScene = lazy(() => import("@/components/funnel/FunnelScene"));

class SceneBoundary extends Component<{ fallback: ReactNode; children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? this.props.fallback : this.props.children;
  }
}

export function LiveFunnel({ data }: { data: FunnelData }) {
  const reduce = useReducedMotion() ?? false;
  const [want3d, setWant3d] = useState(false);

  useEffect(() => {
    if (reduce) return;
    let cancelIdle: (() => void) | undefined;
    const off = onFirstInteraction(() => {
      cancelIdle = whenIdle(() => {
        if (canUseWebGL()) setWant3d(true);
      });
    });
    return () => {
      off();
      cancelIdle?.();
    };
  }, [reduce]);

  const fallback = <FunnelStatic data={data} />;
  if (reduce || !want3d) return fallback;
  return (
    <SceneBoundary fallback={fallback}>
      <Suspense fallback={fallback}>
        <FunnelScene data={data} />
      </Suspense>
    </SceneBoundary>
  );
}
