import { funnelLabel, LEVEL_COLUMN } from "@/components/funnel/geometry";
import { unitHash, type FunnelData } from "@/lib/funnel";
import { ALERT_LEVELS, levelColor, levelLabel } from "@/theme/tokens";

/**
 * Embudo en SVG estático: lo que se ve con `prefers-reduced-motion`, sin WebGL, mientras carga la
 * escena 3D o si falla. Mismas cifras que la escena (de la API). Cada alerta es un punto con su
 * CVE en el `title`; las CVE sin nivel se dibujan como mucho `MAX_STATIC_DOTS` (el texto dice
 * cuántas se dibujan de cuántas).
 */

const W = 900;
const H = 256;
const TOP_Y = 24;
const THROAT_Y = 150;
const PAD_Y = 222;
export const MAX_STATIC_DOTS = 240;

function padX(col: number): number {
  return (W / 3) * col + W / 6;
}

export function FunnelStatic({ data }: { data: FunnelData }) {
  const rest = data.particles.filter((p) => p.level === "none").slice(0, MAX_STATIC_DOTS);
  const alerts = data.particles.filter((p) => p.level !== "none");
  const cx = W / 2;
  const topHalf = W * 0.32;
  const throatHalf = 22;
  return (
    <svg
      data-testid="funnel-static"
      role="img"
      aria-label={funnelLabel(data)}
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="xMidYMid meet"
      className="h-full w-full"
    >
      <path
        d={`M ${cx - topHalf},${TOP_Y} L ${cx + topHalf},${TOP_Y} L ${cx + throatHalf},${THROAT_Y} L ${cx - throatHalf},${THROAT_Y} Z`}
        style={{ fill: "var(--muted)", stroke: "var(--border)" }}
      />
      {[0.25, 0.5, 0.75].map((f) => {
        const y = TOP_Y + (THROAT_Y - TOP_Y) * f;
        const half = topHalf + (throatHalf - topHalf) * f;
        return <line key={f} x1={cx - half} x2={cx + half} y1={y} y2={y} style={{ stroke: "var(--border)" }} />;
      })}
      {rest.map((p) => {
        const s = unitHash(p.id, 2);
        const y = TOP_Y + 8 + (THROAT_Y - TOP_Y - 16) * s;
        const half = topHalf + (throatHalf - topHalf) * ((y - TOP_Y) / (THROAT_Y - TOP_Y)) - 6;
        const x = cx + (unitHash(p.id, 1) * 2 - 1) * Math.max(half, 0);
        return (
          <circle key={p.id} cx={x} cy={y} r={3} style={{ fill: levelColor.none, opacity: 0.7 }}>
            <title>{p.id}</title>
          </circle>
        );
      })}
      {ALERT_LEVELS.map((lv) => {
        const x = padX(LEVEL_COLUMN[lv]);
        return (
          <g key={lv}>
            <path
              d={`M ${cx},${THROAT_Y} Q ${cx},${PAD_Y - 20} ${x},${PAD_Y - 8}`}
              style={{ stroke: levelColor[lv], strokeOpacity: 0.5, fill: "none" }}
              strokeDasharray="3 5"
            />
            <ellipse cx={x} cy={PAD_Y + 6} rx={56} ry={10} style={{ fill: levelColor[lv], opacity: 0.25 }} />
          </g>
        );
      })}
      {alerts.map((p, i) => {
        if (p.level === "none") return null;
        const x = padX(LEVEL_COLUMN[p.level]) + (unitHash(p.id, 1) * 2 - 1) * 40;
        const y = PAD_Y + (unitHash(p.id, 3) * 2 - 1) * 5 - (i % 3);
        return (
          <circle key={p.id} cx={x} cy={y} r={6} style={{ fill: levelColor[p.level], stroke: "var(--background)" }}>
            <title>{`${p.id} · ${levelLabel[p.level]}`}</title>
          </circle>
        );
      })}
    </svg>
  );
}
