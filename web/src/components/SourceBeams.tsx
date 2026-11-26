import { Cpu } from "lucide-react";
import { createRef, useMemo, useRef, type RefObject } from "react";
import { AnimatedBeam } from "@/components/magicui/animated-beam";
import type { RunStatus, SourceHealth } from "@/fixtures/restricted";
import { cn } from "@/lib/utils";

/**
 * Haces de las fuentes al núcleo (Magic UI `animated-beam`). El estado de cada haz sale del mismo
 * dato que la tabla: una fuente en UNKNOWN no tiene haz que fluya, sino un trazo discontinuo en el
 * color de error (fail-closed también en el dibujo).
 */

const BEAM: Record<RunStatus, { animated: boolean; dashed: boolean; color: string; label: string }> = {
  ok: { animated: true, dashed: false, color: "var(--muted-foreground)", label: "OK" },
  partial: { animated: true, dashed: false, color: "var(--level-b)", label: "parcial" },
  unknown: { animated: false, dashed: true, color: "var(--destructive)", label: "UNKNOWN" },
};

export function SourceBeams({ sources }: { sources: SourceHealth[] }) {
  const container = useRef<HTMLDivElement>(null);
  const core = useRef<HTMLDivElement>(null);
  const refs = useMemo<RefObject<HTMLDivElement | null>[]>(() => sources.map(() => createRef<HTMLDivElement>()), [sources]);
  const unknown = sources.filter((s) => s.status === "unknown").length;
  const summary = `${sources.length} fuentes hacia el núcleo; ${unknown} en UNKNOWN: ${sources
    .map((s) => `${s.name} ${BEAM[s.status].label}`)
    .join(", ")}.`;

  return (
    <div
      ref={container}
      data-testid="source-beams"
      role="img"
      aria-label={summary}
      className="relative flex items-center justify-between gap-8 py-2"
    >
      <ul className="z-10 flex flex-col gap-2">
        {sources.map((s, i) => (
          <li key={s.name}>
            <div
              ref={refs[i]}
              data-status={s.status}
              className={cn(
                "flex items-center gap-2 rounded-md border bg-card px-3 py-1 font-mono text-xs shadow-sm",
                s.status === "unknown" && "border-destructive",
              )}
            >
              <span
                aria-hidden="true"
                className={cn(
                  "size-2 rounded-full",
                  s.status === "ok" && "bg-muted-foreground",
                  s.status === "partial" && "bg-level-b",
                  s.status === "unknown" && "bg-destructive",
                )}
              />
              {s.name}
            </div>
          </li>
        ))}
      </ul>
      <div
        ref={core}
        className="z-10 flex flex-col items-center gap-1 rounded-xl border bg-card px-4 py-3 text-sm font-semibold shadow"
      >
        <Cpu aria-hidden="true" className="size-6 text-muted-foreground" />
        Núcleo
      </div>
      {sources.map((s, i) => (
        <AnimatedBeam
          key={s.name}
          containerRef={container}
          fromRef={refs[i]}
          toRef={core}
          curvature={(i - (sources.length - 1) / 2) * -12}
          duration={4 + (i % 3)}
          delay={i * 0.4}
          animated={BEAM[s.status].animated}
          dashed={BEAM[s.status].dashed}
          pathColor={BEAM[s.status].color}
        />
      ))}
    </div>
  );
}
