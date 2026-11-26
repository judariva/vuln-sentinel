import type { ReactNode } from "react";
import { Bar, BarChart, CartesianGrid, Line, LineChart, XAxis, YAxis } from "recharts";
import { getMetricsDaily } from "@/api/client";
import { alertsPerDay, changesByType, detection, funnel, kevLead } from "@/api/metrics";
import type { MetricsDaily } from "@/api/types";
import { LoadError, Loading } from "@/components/States";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/useApi";
import { changeLabel } from "@/lib/format";
import { chartColor, levelColor } from "@/theme/tokens";

export function MetricsPage() {
  const state = useApi("metrics", (signal) => getMetricsDaily(signal));
  return (
    <section aria-labelledby="metricas-titulo" className="space-y-6">
      <h1 id="metricas-titulo" className="text-2xl font-semibold tracking-tight">
        Métricas
      </h1>
      {state.status === "loading" && <Loading />}
      {state.status === "error" && <LoadError error={state.error} />}
      {state.status === "ok" && <MetricsView doc={state.data} />}
    </section>
  );
}

function ChartCard({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>{title}</h2>
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

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

export function MetricsView({ doc }: { doc: MetricsDaily }) {
  const steps = funnel(doc.rows);
  const perDay = alertsPerDay(doc.rows);
  const det = detection(doc.rows);
  const lead = kevLead(doc.rows);
  const types = changesByType(doc.rows).map((t) => ({ ...t, label: changeLabel(t.type) }));
  return (
    <>
      <p className="text-muted-foreground">
        Del {doc.from} al {doc.to} (UTC), precalculadas cada día en la base de datos del producto.
      </p>
      <div className="grid gap-4 lg:grid-cols-2">
        <ChartCard title="Embudo" description="Ingeridas → elegibles → candidatas → A, B o C, en todo el periodo.">
          <ChartContainer config={funnelConfig} className="h-64 w-full" role="img" aria-label="Gráfica del embudo">
            <BarChart data={steps} layout="vertical" margin={{ left: 24 }}>
              <CartesianGrid horizontal={false} />
              <XAxis type="number" scale="sqrt" />
              <YAxis type="category" dataKey="step" width={90} />
              <ChartTooltip content={<ChartTooltipContent />} />
              <Bar dataKey="value" fill="var(--color-value)" radius={4} />
            </BarChart>
          </ChartContainer>
          <Table className="mt-4">
            <TableCaption className="sr-only">Embudo en cifras</TableCaption>
            <TableHeader>
              <TableRow>
                {steps.map((s) => (
                  <TableHead key={s.step} scope="col">
                    {s.step}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow>
                {steps.map((s) => (
                  <TableCell key={s.step} className="font-mono">
                    {s.value.toLocaleString("es-ES")}
                  </TableCell>
                ))}
              </TableRow>
            </TableBody>
          </Table>
        </ChartCard>

        <ChartCard title="Alertas por día y nivel" description="Lo que despierta a alguien: A, B y C de cada día.">
          <ChartContainer config={levelsConfig} className="h-64 w-full" role="img" aria-label="Alertas por día y nivel">
            <BarChart data={perDay}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="day" tickFormatter={(d: string) => d.slice(5)} minTickGap={16} />
              <YAxis allowDecimals={false} width={32} />
              <ChartTooltip content={<ChartTooltipContent />} />
              <ChartLegend content={<ChartLegendContent />} />
              <Bar dataKey="A" stackId="l" fill="var(--color-A)" />
              <Bar dataKey="B" stackId="l" fill="var(--color-B)" />
              <Bar dataKey="C" stackId="l" fill="var(--color-C)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ChartContainer>
        </ChartCard>

        <ChartCard
          title="Tiempo de detección"
          description={`p50 y p95 por nivel, en minutos, del ${det.day ?? "—"}: desde que la fuente publica hasta la alerta.`}
        >
          <ChartContainer config={detectionConfig} className="h-64 w-full" role="img" aria-label="Tiempo de detección por nivel">
            <BarChart data={det.byLevel}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="level" />
              <YAxis width={40} />
              <ChartTooltip content={<ChartTooltipContent />} />
              <ChartLegend content={<ChartLegendContent />} />
              <Bar dataKey="p50" fill="var(--color-p50)" radius={4} />
              <Bar dataKey="p95" fill="var(--color-p95)" radius={4} />
            </BarChart>
          </ChartContainer>
          <Table className="mt-4">
            <TableCaption className="sr-only">Tiempo de detección en cifras</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Nivel</TableHead>
                <TableHead scope="col">p50 (min)</TableHead>
                <TableHead scope="col">p95 (min)</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {det.byLevel.map((d) => (
                <TableRow key={d.level}>
                  <TableCell>{d.level}</TableCell>
                  <TableCell className="font-mono">{d.p50 ?? "—"}</TableCell>
                  <TableCell className="font-mono">{d.p95 ?? "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </ChartCard>

        <ChartCard
          title="Ventaja sobre KEV"
          description="Horas entre la primera alerta B o C y la entrada en CISA KEV (positivo = antes). Precisión ±15 min."
        >
          {lead.length === 0 ? (
            <p className="text-sm text-muted-foreground">Sin altas de KEV con alerta previa en el periodo.</p>
          ) : (
            <ChartContainer config={kevConfig} className="h-64 w-full" role="img" aria-label="Ventaja sobre KEV en horas">
              <LineChart data={lead}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="day" tickFormatter={(d: string) => d.slice(5)} />
                <YAxis width={40} />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Line dataKey="hours" stroke="var(--color-hours)" strokeWidth={2} dot />
              </LineChart>
            </ChartContainer>
          )}
        </ChartCard>

        <ChartCard title="Tipos de cambio" description="Cambios publicados en el feed completo, por tipo.">
          <ChartContainer config={typesConfig} className="h-64 w-full" role="img" aria-label="Cambios por tipo">
            <BarChart data={types} layout="vertical" margin={{ left: 24 }}>
              <CartesianGrid horizontal={false} />
              <XAxis type="number" scale="sqrt" />
              <YAxis type="category" dataKey="label" width={120} />
              <ChartTooltip content={<ChartTooltipContent />} />
              <Bar dataKey="value" fill="var(--color-value)" radius={4} />
            </BarChart>
          </ChartContainer>
        </ChartCard>
      </div>
    </>
  );
}
