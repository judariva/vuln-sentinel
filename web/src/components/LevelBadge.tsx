import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { asLevel, levelClass, levelLabel } from "@/theme/tokens";

/** Insignia de nivel: el mismo color en todo el portal (tokens.css). */
export function LevelBadge({ level, className }: { level: unknown; className?: string }) {
  const lv = asLevel(level);
  return (
    <Badge
      data-level={lv}
      title={levelLabel[lv]}
      aria-label={levelLabel[lv]}
      className={cn("font-semibold", levelClass[lv], className)}
    >
      {lv === "none" ? "—" : lv}
    </Badge>
  );
}
