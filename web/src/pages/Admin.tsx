import { AccessNotice } from "@/components/AccessNotice";
import { LevelBadge } from "@/components/LevelBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AI_COST, APPROVALS, TRACES, VERDICTS } from "@/fixtures/restricted";
import { utc } from "@/lib/format";

const VERDICT_LABEL = { useful: "Útil", noise: "Ruido" } as const;
const OUTCOME_LABEL = {
  confirmed: "Confirma el nivel",
  blocked_downgrade: "Intento de bajar el nivel bloqueado",
  no_change: "Sin cambio",
} as const;

export function AdminPage() {
  const totalUsd = AI_COST.reduce((acc, d) => acc + d.costUsd, 0);
  return (
    <section aria-labelledby="admin-titulo" className="space-y-6">
      <h1 id="admin-titulo" className="text-2xl font-semibold tracking-tight">
        Administración
      </h1>
      <AccessNotice />

      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Cola de aprobación</h2>
          </CardTitle>
          <CardDescription>
            Nada se publica en X ni LinkedIn sin aprobación humana. Las acciones están desactivadas en
            esta versión.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableCaption className="sr-only">Publicaciones pendientes de aprobación</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Alerta</TableHead>
                <TableHead scope="col">Nivel</TableHead>
                <TableHead scope="col">Canal</TableHead>
                <TableHead scope="col">Pedida</TableHead>
                <TableHead scope="col">Acción</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {APPROVALS.map((a) => (
                <TableRow key={`${a.alertId}-${a.channel}`}>
                  <TableCell className="font-mono">{a.alertId}</TableCell>
                  <TableCell>
                    <LevelBadge level={a.level} />
                  </TableCell>
                  <TableCell>{a.channel === "x" ? "X" : "LinkedIn"}</TableCell>
                  <TableCell className="font-mono text-xs">{utc(a.requestedAt)}</TableCell>
                  <TableCell>
                    <Button size="sm" variant="outline" disabled>
                      Aprobar
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>
              <h2>Veredictos</h2>
            </CardTitle>
            <CardDescription>Útil o ruido: alimenta la métrica de precisión.</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {VERDICTS.map((v) => (
                <li key={v.alertId} className="flex items-center justify-between gap-2">
                  <span className="font-mono">{v.alertId}</span>
                  <Badge variant={v.verdict ? "secondary" : "outline"}>
                    {v.verdict ? VERDICT_LABEL[v.verdict] : "Sin veredicto"}
                  </Badge>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>
              <h2>Coste de IA</h2>
            </CardTitle>
            <CardDescription>
              {AI_COST.length} días · {totalUsd.toFixed(2)} USD en total.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableCaption className="sr-only">Coste de IA por día</TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Día</TableHead>
                  <TableHead scope="col">Llamadas</TableHead>
                  <TableHead scope="col">USD</TableHead>
                  <TableHead scope="col">Bajadas bloqueadas</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {AI_COST.map((d) => (
                  <TableRow key={d.day}>
                    <TableCell className="font-mono">{d.day}</TableCell>
                    <TableCell className="font-mono">{d.calls}</TableCell>
                    <TableCell className="font-mono">{d.costUsd.toFixed(2)}</TableCell>
                    <TableCell className="font-mono">{d.blockedDowngrades}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Trazas del agente</h2>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableCaption className="sr-only">Trazas de las llamadas de IA</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Traza</TableHead>
                <TableHead scope="col">Alerta</TableHead>
                <TableHead scope="col">Tipo</TableHead>
                <TableHead scope="col">Pasos</TableHead>
                <TableHead scope="col">Resultado</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {TRACES.map((t) => (
                <TableRow key={t.traceId}>
                  <TableCell className="font-mono text-xs">{t.traceId}</TableCell>
                  <TableCell className="font-mono">{t.alertId}</TableCell>
                  <TableCell>{t.kind === "investigate" ? "Investigación" : "Redacción"}</TableCell>
                  <TableCell className="font-mono">{t.steps}</TableCell>
                  <TableCell>{OUTCOME_LABEL[t.outcome]}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </section>
  );
}
