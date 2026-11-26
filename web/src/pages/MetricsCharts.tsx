/**
 * Gráficas de Métricas (Recharts, vía las gráficas de shadcn). Bloque aparte (T8b): la pantalla
 * pinta antes sus textos y tablas con las cifras de la API, y las gráficas llegan después.
 *
 * Las barras y líneas no se animan (`isAnimationActive={false}`): Recharts anima volviendo a pintar
 * React en cada fotograma y eso bloqueaba el hilo principal (Lighthouse). El movimiento del portal
 * va con Motion y CSS, no en las gráficas.
 */
import { Bar, BarChart, CartesianGrid, Line, LineChart, XAxis, YAxis } from "recharts";
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { chartColor, levelColor } from "@/theme/tokens";

const levelsConfig = {
  A: { label: "A", color: levelColor.A },
  B: { label: "B", color: levelColor.B },
  C: { label: "C", color: levelColor.C },
} satisfies ChartConfig;
const funnelConfig = { value: { label: "CVE", color: chartColor[0] } } satisfies ChartConfig;
const detectionConfig = {
  p50: { label: "p50 (min)", color: chartColor[1] },
  p95: { label: "p95 (min)", color: chartColor[3] },
} satisfies ChartConfig;
const kevConfig = { hours: { label: "Horas antes de KEV", color: chartColor[1] } } satisfies ChartConfig;
const typesConfig = { value: { label: "Cambios", color: chartColor[2] } } satisfies ChartConfig;

export type ChartSpec =
  | { kind: "funnel"; data: { step: string; value: number }[] }
  | { kind: "perDay"; data: { day: string; A: number; B: number; C: number }[] }
  | { kind: "detection"; data: { level: string; p50: number | null; p95: number | null }[] }
  | { kind: "kevLead"; data: { day: string; hours: number }[] }
  | { kind: "types"; data: { type: string; value: number; label: string }[] };

const box = "h-64 w-full";

export default function MetricsChart({ spec, label }: { spec: ChartSpec; label: string }) {
  switch (spec.kind) {
    case "funnel":
      return (
        <ChartContainer config={funnelConfig} className={box} role="img" aria-label={label}>
          <BarChart data={spec.data} layout="vertical" margin={{ left: 24 }}>
            <CartesianGrid horizontal={false} />
            <XAxis type="number" scale="sqrt" />
            <YAxis type="category" dataKey="step" width={90} />
            <ChartTooltip content={<ChartTooltipContent />} />
            <Bar isAnimationActive={false} dataKey="value" fill="var(--color-value)" radius={4} />
          </BarChart>
        </ChartContainer>
      );
    case "perDay":
      return (
        <ChartContainer config={levelsConfig} className={box} role="img" aria-label={label}>
          <BarChart data={spec.data}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="day" tickFormatter={(d: string) => d.slice(5)} minTickGap={16} />
            <YAxis allowDecimals={false} width={32} />
            <ChartTooltip content={<ChartTooltipContent />} />
            <ChartLegend content={<ChartLegendContent />} />
            <Bar isAnimationActive={false} dataKey="A" stackId="l" fill="var(--color-A)" />
            <Bar isAnimationActive={false} dataKey="B" stackId="l" fill="var(--color-B)" />
            <Bar isAnimationActive={false} dataKey="C" stackId="l" fill="var(--color-C)" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ChartContainer>
      );
    case "detection":
      return (
        <ChartContainer config={detectionConfig} className={box} role="img" aria-label={label}>
          <BarChart data={spec.data}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="level" />
            <YAxis width={40} />
            <ChartTooltip content={<ChartTooltipContent />} />
            <ChartLegend content={<ChartLegendContent />} />
            <Bar isAnimationActive={false} dataKey="p50" fill="var(--color-p50)" radius={4} />
            <Bar isAnimationActive={false} dataKey="p95" fill="var(--color-p95)" radius={4} />
          </BarChart>
        </ChartContainer>
      );
    case "kevLead":
      return (
        <ChartContainer config={kevConfig} className={box} role="img" aria-label={label}>
          <LineChart data={spec.data}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="day" tickFormatter={(d: string) => d.slice(5)} />
            <YAxis width={40} />
            <ChartTooltip content={<ChartTooltipContent />} />
            <Line isAnimationActive={false} dataKey="hours" stroke="var(--color-hours)" strokeWidth={2} dot />
          </LineChart>
        </ChartContainer>
      );
    case "types":
      return (
        <ChartContainer config={typesConfig} className={box} role="img" aria-label={label}>
          <BarChart data={spec.data} layout="vertical" margin={{ left: 24 }}>
            <CartesianGrid horizontal={false} />
            <XAxis type="number" scale="sqrt" />
            <YAxis type="category" dataKey="label" width={120} />
            <ChartTooltip content={<ChartTooltipContent />} />
            <Bar isAnimationActive={false} dataKey="value" fill="var(--color-value)" radius={4} />
          </BarChart>
        </ChartContainer>
      );
  }
}
