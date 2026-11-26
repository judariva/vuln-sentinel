import { Activity, Gauge, Radar } from "lucide-react";
import { Link } from "react-router";
import { getAlertsLatest, getAllChanges } from "@/api/client";
import type { LatestAlert } from "@/api/types";
import { LiveFunnel } from "@/components/funnel/LiveFunnel";
import { LevelBadge } from "@/components/LevelBadge";
import { BentoCard, BentoGrid } from "@/components/magicui/bento-grid";
import { formatCount, NumberTicker } from "@/components/magicui/number-ticker";
import { LoadError, Loading } from "@/components/States";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/useApi";
import { changeLabel, utcTime } from "@/lib/format";
import { alertCount, summarizeFunnel, type FunnelData } from "@/lib/funnel";
import { summarizeToday, type TodaySummary } from "@/lib/today";
import { ALERT_LEVELS, levelClass, levelLabel } from "@/theme/tokens";

/** Hoy se vuelve a pedir cada 5 minutos: así se ven entrar alertas y cambiar niveles. */
const REFRESH_MS = 5 * 60_000;

interface TodayData {
  summary: TodaySummary;
  latest: LatestAlert[];
}

async function loadToday(signal: AbortSignal): Promise<TodayData> {
  const [changes, latest] = await Promise.all([getAllChanges("alerts", signal), getAlertsLatest(signal)]);
  return {
    summary: summarizeToday(changes.generatedAt || latest.generated_at, changes.entries, latest.alerts),
    latest: latest.alerts,
  };
}

export function TodayPage() {
  const state = useApi("today", loadToday, REFRESH_MS);
  return (
    <section aria-labelledby="hoy-titulo" className="space-y-6">
      <h1 id="hoy-titulo" className="text-2xl font-semibold tracking-tight">
        Hoy
      </h1>
      {state.status === "loading" && <Loading />}
      {state.status === "error" && <LoadError error={state.error} />}
      {state.status === "ok" && <TodayView summary={state.data.summary} latest={state.data.latest} />}
    </section>
  );
}

export function TodayView({ summary, latest = [] }: { summary: TodaySummary; latest?: LatestAlert[] }) {
  return (
    <>
      <p className="text-muted-foreground">
        Alertas con cambios el {summary.day} (UTC), agrupadas por su nivel actual.
      </p>
      {/* Bento (T8c): embudo en 3 columnas con los KPI al lado; A, B y C debajo, cada una bajo su
          plataforma; los cambios del día a lo ancho. */}
      <BentoGrid className="lg:grid-cols-4">
          <FunnelTile latest={latest} changes={summary.changes.length} />
          {ALERT_LEVELS.map((lv) => {
            const items = summary.byLevel[lv];
            return (
              <BentoCard
                key={lv}
                data-testid={`level-${lv}`}
                headingId={`hoy-nivel-${lv}`}
                name={
                  <>
                    <LevelBadge level={lv} />
                    <span>
                      <NumberTicker value={items.length} /> {items.length === 1 ? "alerta" : "alertas"}
                    </span>
                  </>
                }
                description={levelLabel[lv]}
              >
                {items.length === 0 ? (
                  <p className="text-sm text-muted-foreground">Ninguna hoy.</p>
                ) : (
                  <ul className="space-y-3">
                    {items.map((a) => (
                      // La clave lleva el nivel: si una alerta cambia de nivel en un refresco, entra
                      // de nuevo en su tarjeta (animación CSS, sin coste en el hilo principal).
                      <li
                        key={`${lv}-${a.id}`}
                        className="space-y-1 motion-safe:animate-in motion-safe:slide-in-from-left-2 motion-safe:duration-500"
                      >
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
              </BentoCard>
            );
          })}

          <BentoCard
            className="md:col-span-3 lg:col-span-4"
            headingId="hoy-cambios"
            Icon={Activity}
            name={
              <>
                Cambios del día
                <Badge variant="secondary" className="font-mono">
                  <NumberTicker value={summary.changes.length} />
                </Badge>
              </>
            }
            description="Del feed de alertas, del más reciente al más antiguo."
          >
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
          </BentoCard>
        </BentoGrid>
    </>
  );
}

/**
 * Reparto del día por nivel: una barra apilada (decorativa, `aria-hidden`) y su leyenda con las
 * mismas cifras en texto. Las alertas tienen un ancho mínimo para que se vean junto a cientos de
 * CVE sin nivel; el texto lleva siempre la cifra exacta.
 */
function LevelShare({ data }: { data: FunnelData }) {
  const levels = [...ALERT_LEVELS, "none"] as const;
  return (
    <div className="mt-6 space-y-2" data-testid="funnel-share">
      <p className="text-sm text-muted-foreground">Reparto por nivel</p>
      <div aria-hidden="true" className="flex h-3 w-full gap-0.5 overflow-hidden rounded-full">
        {levels.map((lv) =>
          data.counts[lv] > 0 ? (
            <div
              key={lv}
              className={`${levelClass[lv]} ${lv === "none" ? "opacity-40" : ""}`}
              style={{ flexGrow: data.counts[lv], flexBasis: lv === "none" ? 0 : "0.75rem" }}
            />
          ) : null,
        )}
      </div>
      <ul className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-xs text-muted-foreground">
        {levels.map((lv) => (
          <li key={lv}>
            {lv === "none" ? "sin nivel" : lv} {formatCount(data.counts[lv])}
          </li>
        ))}
      </ul>
    </div>
  );
}

async function loadFunnel(signal: AbortSignal) {
  return getAllChanges("all", signal);
}

/**
 * Embudo del día: su propia petición (feed completo). Se monta cuando los datos de Hoy ya están
 * pintados y, si falla, solo falla esta tarjeta.
 */
function FunnelTile({ latest, changes }: { latest: LatestAlert[]; changes: number }) {
  const state = useApi("today-funnel", loadFunnel, REFRESH_MS);
  const data: FunnelData | null =
    state.status === "ok"
      ? summarizeFunnel(state.data.generatedAt, state.data.entries, latest, state.data.complete)
      : null;
  return (
    <>
      <BentoCard
        className="md:col-span-3"
        data-testid="funnel"
        data-total={data?.total}
        data-complete={data ? String(data.complete) : undefined}
        headingId="hoy-embudo"
        Icon={Radar}
        name="Embudo del día"
        description="Cada CVE con cambios hoy en el feed completo entra en el embudo; las que acaban en A, B o C caen sobre su tarjeta."
      >
        {/* Alto fijo: lo que hay debajo (las tarjetas) no salta cuando llega el embudo. */}
        <div className="flex h-[22rem] flex-col">
          {state.status === "error" && <LoadError error={state.error} />}
          {data && (
            <>
              <div className="min-h-0 flex-1">
                <LiveFunnel data={data} />
              </div>
              {data.particles.length < data.total ? (
                <p className="text-xs text-muted-foreground">
                  Se dibujan {formatCount(data.particles.length)} de {formatCount(data.total)} (todas las alertas).
                </p>
              ) : null}
              {!data.complete ? (
                <p className="text-xs text-muted-foreground">El feed tenía más páginas: la cifra es un mínimo.</p>
              ) : null}
            </>
          )}
        </div>
      </BentoCard>
      <BentoCard
        className="md:col-span-3 lg:col-span-1 lg:row-span-2"
        data-testid="funnel-kpi"
        headingId="hoy-kpi"
        Icon={Gauge}
        name="El día en cifras"
      >
        <dl className="grid grid-cols-2 gap-5 text-sm sm:grid-cols-4 lg:grid-cols-1 lg:gap-7">
          <div>
            <dt className="text-muted-foreground">CVE con cambios hoy</dt>
            <dd className="text-4xl font-semibold tabular-nums">
              {data ? (
                <>
                  {data.complete ? "" : "≥ "}
                  <NumberTicker value={data.total} />
                </>
              ) : (
                "—"
              )}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Acaban en alerta (A, B o C)</dt>
            <dd className="text-4xl font-semibold tabular-nums">
              {data ? <NumberTicker value={alertCount(data)} /> : "—"}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Sin nivel (solo al resumen diario)</dt>
            <dd className="text-4xl font-semibold tabular-nums">
              {data ? <NumberTicker value={data.counts.none} /> : "—"}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Cambios del feed de alertas</dt>
            <dd className="text-4xl font-semibold tabular-nums">
              <NumberTicker value={changes} />
            </dd>
          </div>
        </dl>
        {data && data.total > 0 ? <LevelShare data={data} /> : null}
      </BentoCard>
    </>
  );
}
