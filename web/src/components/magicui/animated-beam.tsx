/**
 * Haz animado entre dos nodos. Adaptado de Magic UI `animated-beam` (MIT, ver LICENSE-magicui.md).
 *
 * Cambios: colores por variable CSS del tema (en `style`, no como atributo), `animated=false` deja
 * solo el trazo (fuente caída o `prefers-reduced-motion`), `dashed` para el trazo de una fuente en
 * UNKNOWN, y el trazado se calcula solo desde el `ResizeObserver` (que avisa al observar).
 */
import { useReducedMotion } from "motion/react";
import * as m from "motion/react-m";
import { useEffect, useId, useState, type RefObject } from "react";
import { cn } from "@/lib/utils";

export interface AnimatedBeamProps {
  className?: string;
  containerRef: RefObject<HTMLElement | null>;
  fromRef: RefObject<HTMLElement | null>;
  toRef: RefObject<HTMLElement | null>;
  curvature?: number;
  reverse?: boolean;
  /** Color del trazo base: `var(--…)` de `tokens.css`. */
  pathColor?: string;
  pathWidth?: number;
  pathOpacity?: number;
  gradientStartColor?: string;
  gradientStopColor?: string;
  delay?: number;
  duration?: number;
  animated?: boolean;
  dashed?: boolean;
}

export function AnimatedBeam({
  className,
  containerRef,
  fromRef,
  toRef,
  curvature = 0,
  reverse = false,
  duration = 5,
  delay = 0,
  pathColor = "var(--muted-foreground)",
  pathWidth = 2,
  pathOpacity = 0.25,
  gradientStartColor = "var(--chart-2)",
  gradientStopColor = "var(--chart-1)",
  animated = true,
  dashed = false,
}: AnimatedBeamProps) {
  // `useId` puede traer caracteres que no valen en `url(#…)`.
  const id = `beam-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const reduce = useReducedMotion() ?? false;
  const [pathD, setPathD] = useState("");
  const [size, setSize] = useState({ width: 0, height: 0 });

  const gradient = reverse
    ? { x1: ["90%", "-10%"], x2: ["100%", "0%"], y1: ["0%", "0%"], y2: ["0%", "0%"] }
    : { x1: ["10%", "110%"], x2: ["0%", "100%"], y1: ["0%", "0%"], y2: ["0%", "0%"] };

  useEffect(() => {
    const update = () => {
      if (!containerRef.current || !fromRef.current || !toRef.current) return;
      const c = containerRef.current.getBoundingClientRect();
      const a = fromRef.current.getBoundingClientRect();
      const b = toRef.current.getBoundingClientRect();
      setSize({ width: c.width, height: c.height });
      const sx = a.left - c.left + a.width;
      const sy = a.top - c.top + a.height / 2;
      const ex = b.left - c.left;
      const ey = b.top - c.top + b.height / 2;
      setPathD(`M ${sx},${sy} Q ${(sx + ex) / 2},${sy - curvature} ${ex},${ey}`);
    };
    const ro = new ResizeObserver(update);
    if (containerRef.current) ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, [containerRef, fromRef, toRef, curvature]);

  const moving = animated && !reduce;
  return (
    <svg
      fill="none"
      width={size.width}
      height={size.height}
      aria-hidden="true"
      focusable="false"
      className={cn("pointer-events-none absolute top-0 left-0 transform-gpu", className)}
      viewBox={`0 0 ${size.width} ${size.height}`}
    >
      <path
        d={pathD}
        strokeWidth={pathWidth}
        strokeLinecap="round"
        strokeDasharray={dashed ? "4 6" : undefined}
        style={{ stroke: pathColor, strokeOpacity: dashed ? 0.9 : pathOpacity }}
      />
      {moving ? (
        <>
          <path d={pathD} strokeWidth={pathWidth} stroke={`url(#${id})`} strokeLinecap="round" />
          <defs>
            <m.linearGradient
              id={id}
              gradientUnits="userSpaceOnUse"
              initial={{ x1: "0%", x2: "0%", y1: "0%", y2: "0%" }}
              animate={gradient}
              transition={{ delay, duration, ease: [0.16, 1, 0.3, 1], repeat: Infinity }}
            >
              <stop style={{ stopColor: gradientStartColor, stopOpacity: 0 }} />
              <stop style={{ stopColor: gradientStartColor }} />
              <stop offset="32.5%" style={{ stopColor: gradientStopColor }} />
              <stop offset="100%" style={{ stopColor: gradientStopColor, stopOpacity: 0 }} />
            </m.linearGradient>
          </defs>
        </>
      ) : null}
    </svg>
  );
}
