import * as m from "motion/react-m";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { asLevel, levelClass, levelLabel } from "@/theme/tokens";

/**
 * Insignia de nivel: el mismo color en todo el portal (tokens.css). Si el nivel cambia mientras
 * está en pantalla (refresco de Hoy), late una vez. Con `prefers-reduced-motion` no se mueve
 * (`MotionConfig reducedMotion="user"` en `main.tsx`).
 */
export function LevelBadge({ level, className }: { level: unknown; className?: string }) {
  const lv = asLevel(level);
  const [prev, setPrev] = useState(lv);
  const [changes, setChanges] = useState(0);
  if (prev !== lv) {
    setPrev(lv);
    setChanges((n) => n + 1);
  }
  const badge = (
    <Badge
      data-level={lv}
      title={levelLabel[lv]}
      aria-label={levelLabel[lv]}
      className={cn("font-semibold", levelClass[lv], className)}
    >
      {lv === "none" ? "—" : lv}
    </Badge>
  );
  // Sin cambios, una insignia normal: Motion solo entra cuando hay algo que animar.
  if (changes === 0) return badge;
  return (
    <m.span
      key={changes}
      className="inline-flex"
      initial={{ scale: 1.35 }}
      animate={{ scale: 1 }}
      transition={{ type: "spring", stiffness: 400, damping: 15 }}
    >
      {badge}
    </m.span>
  );
}
