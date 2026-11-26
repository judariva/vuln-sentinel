import { lazy, startTransition, Suspense, useEffect, useRef, useState, type ReactNode } from "react";
import { getMetricsDaily } from "@/api/client";
import { alertsPerDay, changesByType, detection, funnel, kevLead } from "@/api/metrics";
import type { MetricsDaily } from "@/api/types";
import { LoadError, Loading } from "@/components/States";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/useApi";
import { useVisible } from "@/hooks/useVisible";
import { whenIdle } from "@/lib/capabilities";
import { changeLabel } from "@/lib/format";
import type { ChartSpec } from "@/pages/MetricsCharts";

// Recharts va en su propio bloque (T8b): los textos y las tablas con las cifras se pintan antes.
const MetricsChart = lazy(() => import("@/pages/MetricsCharts"));

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

/**
 * Gráfica que se monta al acercarse a la pantalla y con el navegador libre (T8b). Recharts mide y
 * maqueta al montar: las cinco a la vez, junto con los datos, bloqueaban el hilo principal. Así
 * cada una va en su propia tarea, después de las tablas. El hueco tiene el mismo alto (sin saltos)
 * y las cifras que importan están además en tablas, que se pintan siempre.
 */
function LazyChart({ spec, label }: { spec: ChartSpec; label: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const visible = useVisible(ref);
  const [idle, setIdle] = useState(false);
  useEffect(() => {
    if (!visible) return;
    // En una transición: React puede trocear el render de Recharts en vez de una sola tarea larga.
    return whenIdle(() => startTransition(() => setIdle(true)));
  }, [visible]);
  return (
    <div ref={ref} className="h-64 w-full">
      {visible && idle ? (
        <Suspense fallback={null}>
          <MetricsChart spec={spec} label={label} />
        </Suspense>
      ) : null}
    </div>
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
          <LazyChart spec={{ kind: "funnel", data: steps }} label="Gráfica del embudo" />
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
          <LazyChart spec={{ kind: "perDay", data: perDay }} label="Alertas por día y nivel" />
        </ChartCard>

        <ChartCard
          title="Tiempo de detección"
          description={`p50 y p95 por nivel, en minutos, del ${det.day ?? "—"}: desde que la fuente publica hasta la alerta.`}
        >
          <LazyChart spec={{ kind: "detection", data: det.byLevel }} label="Tiempo de detección por nivel" />
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
            <LazyChart spec={{ kind: "kevLead", data: lead }} label="Ventaja sobre KEV en horas" />
          )}
        </ChartCard>

        <ChartCard title="Tipos de cambio" description="Cambios publicados en el feed completo, por tipo.">
          <LazyChart spec={{ kind: "types", data: types }} label="Cambios por tipo" />
        </ChartCard>
      </div>
    </>
  );
}
