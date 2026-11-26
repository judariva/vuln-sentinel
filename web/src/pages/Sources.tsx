import { AccessNotice } from "@/components/AccessNotice";
import { SourceBeams } from "@/components/SourceBeams";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SOURCES, type RunStatus } from "@/fixtures/restricted";
import { utc } from "@/lib/format";

const STATUS: Record<RunStatus, { label: string; variant: "secondary" | "outline" | "destructive" }> = {
  ok: { label: "OK", variant: "secondary" },
  partial: { label: "Parcial", variant: "outline" },
  unknown: { label: "UNKNOWN", variant: "destructive" },
};

export function SourcesPage() {
  const unknown = SOURCES.filter((s) => s.status === "unknown");
  return (
    <section aria-labelledby="fuentes-titulo" className="space-y-6">
      <h1 id="fuentes-titulo" className="text-2xl font-semibold tracking-tight">
        Fuentes
      </h1>
      <AccessNotice />
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Flujo hacia el núcleo</h2>
          </CardTitle>
          <CardDescription>Cada fuente alimenta el núcleo; una caída se ve cortada.</CardDescription>
        </CardHeader>
        <CardContent>
          <SourceBeams sources={SOURCES} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Salud y última ejecución</h2>
          </CardTitle>
          <CardDescription>
            Una fuente caída sale como UNKNOWN, nunca como «sin novedades». Hoy: {unknown.length} en UNKNOWN.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableCaption className="sr-only">Estado de cada fuente</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Fuente</TableHead>
                <TableHead scope="col">Estado</TableHead>
                <TableHead scope="col">Última ejecución</TableHead>
                <TableHead scope="col">Último dato publicado</TableHead>
                <TableHead scope="col">Vistos / nuevos</TableHead>
                <TableHead scope="col">Umbral</TableHead>
                <TableHead scope="col">Error</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {SOURCES.map((s) => (
                <TableRow key={s.name} data-status={s.status}>
                  <TableCell className="font-mono">{s.name}</TableCell>
                  <TableCell>
                    <Badge variant={STATUS[s.status].variant}>{STATUS[s.status].label}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{utc(s.lastRunAt)}</TableCell>
                  <TableCell className="font-mono text-xs">{utc(s.lastItemPublishedAt)}</TableCell>
                  <TableCell className="font-mono">
                    {s.itemsSeen.toLocaleString("es-ES")} / {s.itemsNew.toLocaleString("es-ES")}
                  </TableCell>
                  <TableCell className="font-mono">{s.freshnessMinutes} min</TableCell>
                  <TableCell className="whitespace-normal text-sm">{s.error ?? "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </section>
  );
}
