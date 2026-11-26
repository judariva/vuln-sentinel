import { formatCount } from "@/components/magicui/number-ticker";
import type { FunnelData } from "@/lib/funnel";
import { ALERT_LEVELS, levelClass, levelLabel } from "@/theme/tokens";

/**
 * Etiquetas de los destinos del embudo, en HTML y fuera de la escena (T8c): una columna por nivel,
 * bajo su plataforma y alineada con su tarjeta de Hoy. Las comparten la escena 3D y el SVG; así no
 * se solapan con las partículas y se leen con lector de pantalla. Las cifras, de la API.
 */
export function FunnelLabels({ data }: { data: FunnelData }) {
  return (
    <ul className="grid grid-cols-3 gap-2 pt-2 text-center" aria-label="Destinos del embudo">
      {ALERT_LEVELS.map((lv) => (
        <li key={lv} className="flex flex-col items-center gap-0.5">
          <span
            data-testid={`funnel-pad-${lv}`}
            className={`rounded px-2 py-0.5 font-mono text-sm font-semibold ${levelClass[lv]}`}
          >
            {lv} · {formatCount(data.counts[lv])}
          </span>
          <span className="hidden text-xs text-muted-foreground sm:block">{levelLabel[lv].split(" · ")[1]}</span>
        </li>
      ))}
    </ul>
  );
}
