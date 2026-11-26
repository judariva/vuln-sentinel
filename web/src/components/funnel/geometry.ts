import type { FunnelData } from "@/lib/funnel";
import { formatCount } from "@/components/magicui/number-ticker";
import { ALERT_LEVELS, type Level } from "@/theme/tokens";

/** Texto accesible común a la versión 3D y a la estática: las mismas cifras de la API. */
export function funnelLabel(data: FunnelData): string {
  const total = `${data.complete ? "" : "al menos "}${formatCount(data.total)}`;
  const parts = ALERT_LEVELS.map((lv) => `${lv}: ${formatCount(data.counts[lv])}`).join(", ");
  return `Embudo del ${data.day}: ${total} CVE con cambios; acaban en alerta ${parts}.`;
}

/** Columna (0, 1, 2) de la tarjeta de cada nivel en la rejilla de Hoy. */
export const LEVEL_COLUMN: Record<Exclude<Level, "none">, number> = { A: 0, B: 1, C: 2 };
