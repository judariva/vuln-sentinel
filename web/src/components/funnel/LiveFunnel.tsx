import { useReducedMotion } from "motion/react";
import { Component, lazy, Suspense, useEffect, useState, type ReactNode } from "react";
import { FunnelStatic } from "@/components/funnel/FunnelStatic";
import { FunnelLabels } from "@/components/funnel/FunnelLabels";
import { afterLoadIdle, canUseWebGL, whenIdle } from "@/lib/capabilities";
import type { FunnelData } from "@/lib/funnel";

/**
 * Elige entre la escena 3D y el SVG estático. Robustez (T8b; carga revisada en T8c, ADR-0024):
 * - la escena es otro bloque (`lazy`) y se pide **sola, al llegar**, pero después de pintar los
 *   datos: `load` del documento → dos fotogramas → navegador libre. Entonces se descarga y evalúa el
 *   bloque; montar el `Canvas` va en otro momento libre, para partir el trabajo en dos tareas.
 *   Mientras llega, y si falla, se ve el SVG con las mismas cifras;
 * - con `prefers-reduced-motion` o sin WebGL nunca se pide.
 * Las etiquetas de los destinos (A, B, C) van en HTML bajo el lienzo, iguales en las dos versiones.
 */
const loadScene = () => import("@/components/funnel/FunnelScene");
const FunnelScene = lazy(loadScene);

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
    let cancelMount: (() => void) | undefined;
    let alive = true;
    const cancelLoad = afterLoadIdle(() => {
      if (!canUseWebGL()) return;
      loadScene().then(
        () => {
          if (alive) cancelMount = whenIdle(() => setWant3d(true));
        },
        // Si el bloque no llega, se queda el SVG (no se monta nada que vuelva a fallar).
        () => undefined,
      );
    });
    return () => {
      alive = false;
      cancelLoad();
      cancelMount?.();
    };
  }, [reduce]);

  const fallback = <FunnelStatic data={data} />;
  return (
    <div className="flex h-full flex-col">
      <div className="min-h-0 flex-1">
        {reduce || !want3d ? (
          fallback
        ) : (
          <SceneBoundary fallback={fallback}>
            <Suspense fallback={fallback}>
              <FunnelScene data={data} />
            </Suspense>
          </SceneBoundary>
        )}
      </div>
      <FunnelLabels data={data} />
    </div>
  );
}
