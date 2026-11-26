import { Link } from "react-router";
import { getAlertsLatest, getAllChanges } from "@/api/client";
import { LevelBadge } from "@/components/LevelBadge";
import { LoadError, Loading } from "@/components/States";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/useApi";
import { changeLabel, utcTime } from "@/lib/format";
import { summarizeToday, type TodaySummary } from "@/lib/today";
import { ALERT_LEVELS, levelLabel } from "@/theme/tokens";

async function loadToday(signal: AbortSignal): Promise<TodaySummary> {
  const [changes, latest] = await Promise.all([getAllChanges("alerts", signal), getAlertsLatest(signal)]);
  return summarizeToday(changes.generatedAt || latest.generated_at, changes.entries, latest.alerts);
}

export function TodayPage() {
  const state = useApi("today", loadToday);
  return (
    <section aria-labelledby="hoy-titulo" className="space-y-6">
      <h1 id="hoy-titulo" className="text-2xl font-semibold tracking-tight">
        Hoy
      </h1>
      {state.status === "loading" && <Loading />}
      {state.status === "error" && <LoadError error={state.error} />}
      {state.status === "ok" && <TodayView summary={state.data} />}
    </section>
  );
}

export function TodayView({ summary }: { summary: TodaySummary }) {
  return (
    <>
      <p className="text-muted-foreground">
        Alertas con cambios el {summary.day} (UTC), agrupadas por su nivel actual.
      </p>
      <div className="grid gap-4 md:grid-cols-3">
        {ALERT_LEVELS.map((lv) => (
          <Card key={lv} data-testid={`level-${lv}`}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <LevelBadge level={lv} />
                <span>
                  {summary.byLevel[lv].length} {summary.byLevel[lv].length === 1 ? "alerta" : "alertas"}
                </span>
              </CardTitle>
              <CardDescription>{levelLabel[lv]}</CardDescription>
            </CardHeader>
            <CardContent>
              {summary.byLevel[lv].length === 0 ? (
                <p className="text-sm text-muted-foreground">Ninguna hoy.</p>
              ) : (
                <ul className="space-y-3">
                  {summary.byLevel[lv].map((a) => (
                    <li key={a.id} className="space-y-1">
                      <Link to={`/alertas/${a.id}`} className="font-mono text-sm underline underline-offset-4">
                        {a.id}
                      </Link>
                      <div className="flex flex-wrap gap-1">
                        {a.types.map((t) => (
                          <Badge key={t} variant="outline">
                            {changeLabel(t)}
                          </Badge>
                        ))}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Cambios del día</h2>
          </CardTitle>
          <CardDescription>Del feed de alertas, del más reciente al más antiguo.</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableCaption className="sr-only">Cambios del feed de alertas el {summary.day}</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Hora (UTC)</TableHead>
                <TableHead scope="col">Alerta</TableHead>
                <TableHead scope="col">Cambio</TableHead>
                <TableHead scope="col">Nivel</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {summary.changes.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-muted-foreground">
                    Sin cambios hoy.
                  </TableCell>
                </TableRow>
              ) : (
                summary.changes.map((c) => (
                  <TableRow key={`${c.id}-${c.modified}`}>
                    <TableCell className="font-mono">{utcTime(c.modified)}</TableCell>
                    <TableCell>
                      <Link to={`/alertas/${c.id}`} className="font-mono underline underline-offset-4">
                        {c.id}
                      </Link>
                    </TableCell>
                    <TableCell>{changeLabel(c.type)}</TableCell>
                    <TableCell>
                      <LevelBadge level={c.level} />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </>
  );
}
