import { Link, useParams } from "react-router";
import { getVuln } from "@/api/client";
import type { Affected, VulnRecord } from "@/api/types";
import { ExternalLink } from "@/components/ExternalLink";
import { LevelBadge } from "@/components/LevelBadge";
import { LoadError, Loading } from "@/components/States";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/useApi";
import { utc } from "@/lib/format";
import { buildTimeline, describeEvents } from "@/lib/timeline";
import { levelColor, asLevel } from "@/theme/tokens";

export function AlertDetailPage() {
  const { id = "" } = useParams();
  const state = useApi(`vuln:${id}`, (signal) => getVuln(id, signal));
  return (
    <section aria-labelledby="detalle-titulo" className="space-y-6">
      <p>
        <Link to="/" className="text-sm text-muted-foreground underline underline-offset-4">
          ← Hoy
        </Link>
      </p>
      {state.status === "loading" && (
        <>
          <h1 id="detalle-titulo" className="font-mono text-2xl font-semibold">
            {id}
          </h1>
          <Loading />
        </>
      )}
      {state.status === "error" && (
        <>
          <h1 id="detalle-titulo" className="font-mono text-2xl font-semibold">
            {id}
          </h1>
          <LoadError error={state.error} />
        </>
      )}
      {state.status === "ok" && <AlertDetailView record={state.data} />}
    </section>
  );
}

function productName(a: Affected): string {
  const ds = a.database_specific ?? {};
  if (a.package) return a.package.name;
  return [ds.vendor, ds.product].filter(Boolean).join(" ") || "—";
}

export function AlertDetailView({ record }: { record: VulnRecord }) {
  const ext = record.database_specific.vuln_sentinel;
  const sig = ext.signals;
  const timeline = buildTimeline(record);
  return (
    <>
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-3">
          <h1 id="detalle-titulo" className="font-mono text-2xl font-semibold">
            {record.id}
          </h1>
          <LevelBadge level={ext.level} className="text-sm" />
          {record.withdrawn ? <Badge variant="destructive">Retirada</Badge> : null}
        </div>
        {record.summary ? <p>{record.summary}</p> : null}
        <p className="text-sm text-muted-foreground">
          Alias: {(record.aliases ?? []).join(", ") || "—"} · Impacto: {ext.impact_class} · Publicada{" "}
          {utc(record.published)} · Modificada {utc(record.modified)}
        </p>
        {ext.level_reason.length > 0 && (
          <div className="flex flex-wrap gap-1" aria-label="Motivos del nivel">
            {ext.level_reason.map((r) => (
              <Badge key={r} variant="outline" className="font-mono">
                {r}
              </Badge>
            ))}
          </div>
        )}
      </header>

      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Productos y rangos</h2>
          </CardTitle>
          <CardDescription>Versiones afectadas según cada fuente. Corregida en: {sig.fix.versions.join(", ") || "sin versión corregida conocida"}.</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableCaption className="sr-only">Productos afectados y rangos de versiones</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Producto</TableHead>
                <TableHead scope="col">Ecosistema / CPE</TableHead>
                <TableHead scope="col">Rangos afectados</TableHead>
                <TableHead scope="col">Origen del rango</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(record.affected ?? []).length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-muted-foreground">
                    Sin productos todavía.
                  </TableCell>
                </TableRow>
              ) : (
                (record.affected ?? []).map((a, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-medium">{productName(a)}</TableCell>
                    <TableCell className="font-mono text-xs whitespace-normal break-all">
                      {a.package?.ecosystem ?? a.database_specific?.cpe?.join(", ") ?? "—"}
                    </TableCell>
                    <TableCell className="whitespace-normal">
                      {(a.ranges ?? []).map((r) => describeEvents(r.events)).join(" · ") ||
                        (a.versions ?? []).join(", ") ||
                        "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{a.database_specific?.range_source ?? "—"}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Señales</h2>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-[auto_1fr]">
            <dt className="text-muted-foreground">CISA KEV</dt>
            <dd>{sig.kev.cisa ? `Sí, observado ${utc(sig.kev.observed_at)}` : "No"}</dd>
            <dt className="text-muted-foreground">SSVC</dt>
            <dd>
              {sig.ssvc
                ? `explotación ${sig.ssvc.exploitation ?? "?"} · automatizable ${sig.ssvc.automatable ?? "?"} · impacto ${sig.ssvc.technical_impact ?? "?"}`
                : "—"}
            </dd>
            <dt className="text-muted-foreground">EPSS</dt>
            <dd>
              {sig.epss && sig.epss.score !== null
                ? `${sig.epss.score} (percentil ${sig.epss.percentile ?? "?"}, ${sig.epss.date ?? "?"})`
                : "—"}
            </dd>
            <dt className="text-muted-foreground">Exploits</dt>
            <dd>
              {sig.exploits.length === 0 ? (
                "Ninguno conocido"
              ) : (
                <ul className="space-y-1">
                  {sig.exploits.map((x, i) => (
                    <li key={i}>
                      <span className="font-mono">{x.rule ?? "?"}</span>
                      {x.status ? ` · ${x.status}` : ""} · <ExternalLink href={x.url} />
                    </li>
                  ))}
                </ul>
              )}
            </dd>
            <dt className="text-muted-foreground">Parche</dt>
            <dd>{sig.fix.available ? sig.fix.versions.join(", ") : "No disponible"}</dd>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Línea de tiempo</h2>
          </CardTitle>
          <CardDescription>
            Dos marcas por hecho: cuándo lo publicó la fuente y cuándo lo observó el monitor.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table data-testid="timeline">
            <TableCaption className="sr-only">Línea de tiempo de la alerta</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Hecho</TableHead>
                <TableHead scope="col">Publicado en la fuente</TableHead>
                <TableHead scope="col">Observado</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {timeline.map((e) => (
                <TableRow key={e.key}>
                  <TableCell className="whitespace-normal">
                    <span className="inline-flex items-center gap-2">
                      {e.level ? (
                        <span
                          aria-hidden="true"
                          className="inline-block size-2.5 rounded-full"
                          style={{ background: levelColor[asLevel(e.level)] }}
                        />
                      ) : null}
                      {e.url ? <ExternalLink href={e.url}>{e.what}</ExternalLink> : e.what}
                    </span>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{utc(e.sourcePublishedAt)}</TableCell>
                  <TableCell className="font-mono text-xs">{utc(e.observedAt)}</TableCell>
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
              <h2>Fuentes</h2>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {ext.sources.map((s) => (
                <li key={s.name}>
                  <span className="font-mono">{s.name}</span> · <ExternalLink href={s.url} />
                </li>
              ))}
              {(record.references ?? [])
                .filter((r) => !ext.sources.some((s) => s.url === r.url))
                .map((r) => (
                  <li key={r.url}>
                    <span className="text-muted-foreground">{r.type}</span> · <ExternalLink href={r.url} />
                  </li>
                ))}
            </ul>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>
              <h2>Expediente de IA</h2>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground">
              {ext.ai.used
                ? "El investigador revisó esta alerta. La IA nunca baja el nivel."
                : "Sin expediente: el nivel es solo determinista."}
            </p>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
