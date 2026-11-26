/**
 * Contador de KPI. Adaptado de Magic UI `number-ticker` (MIT, ver LICENSE-magicui.md).
 *
 * Cambios: la cifra real va siempre en el DOM para lectores de pantalla (`sr-only`) y en
 * `data-value`; lo animado es solo decorativo (`aria-hidden`). Con `prefers-reduced-motion` se pinta
 * el valor sin animar. Formato `es-ES` y colores del tema. Sin `useInView` (los KPI están arriba).
 */
import { useMotionValue, useReducedMotion, useSpring } from "motion/react";
import { useEffect, useRef, type ComponentPropsWithoutRef } from "react";
import { cn } from "@/lib/utils";

interface NumberTickerProps extends ComponentPropsWithoutRef<"span"> {
  value: number;
  startValue?: number;
  delay?: number;
}

const fmt = new Intl.NumberFormat("es-ES", { maximumFractionDigits: 0 });

export function formatCount(n: number): string {
  return fmt.format(n);
}

export function NumberTicker({ value, startValue = 0, delay = 0, className, ...props }: NumberTickerProps) {
  const reduce = useReducedMotion() ?? false;
  const ref = useRef<HTMLSpanElement>(null);
  const motionValue = useMotionValue(reduce ? value : startValue);
  // Muelle más rápido que el de Magic UI (damping 60, stiffness 100): menos fotogramas con trabajo.
  const springValue = useSpring(motionValue, { damping: 40, stiffness: 220, restDelta: 0.5 });

  useEffect(() => {
    if (reduce) {
      motionValue.jump(value);
      springValue.jump(value);
      if (ref.current) ref.current.textContent = formatCount(value);
      return;
    }
    const timer = setTimeout(() => motionValue.set(value), delay * 1000);
    return () => clearTimeout(timer);
  }, [motionValue, springValue, value, delay, reduce]);

  useEffect(
    () =>
      springValue.on("change", (latest) => {
        // Solo se toca el DOM si cambia la cifra que se ve (cada escritura obliga a maquetar).
        const text = formatCount(Math.round(latest));
        if (ref.current && ref.current.textContent !== text) ref.current.textContent = text;
      }),
    [springValue],
  );

  return (
    <span className={cn("inline-block tabular-nums", className)} data-value={value} {...props}>
      <span ref={ref} aria-hidden="true">
        {formatCount(reduce ? value : startValue)}
      </span>
      <span className="sr-only">{formatCount(value)}</span>
    </span>
  );
}
