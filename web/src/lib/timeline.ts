import type { VulnRecord } from "@/api/types";
import { changeLabel } from "@/lib/format";

/**
 * Línea de tiempo del detalle con las DOS marcas de tiempo de todo hecho (CLAUDE.md):
 * `source_published_at` (cuándo lo publicó la fuente) y `observed_at` (cuándo lo vio vuln-sentinel).
 * Los actos propios (cambios de nivel, publicación) no tienen fuente: solo `at`, en «observado».
 */
export interface TimelineEvent {
  key: string;
  what: string;
  kind: "source" | "signal" | "level" | "change";
  sourcePublishedAt: string | null;
  observedAt: string | null;
  url?: string | null;
  level?: string;
}

function sortKey(e: TimelineEvent): string {
  return e.observedAt ?? e.sourcePublishedAt ?? "";
}

export function buildTimeline(rec: VulnRecord): TimelineEvent[] {
  const ext = rec.database_specific.vuln_sentinel;
  const out: TimelineEvent[] = [];
  for (const s of ext.sources) {
    out.push({
      key: `source-${s.name}`,
      what: `Fuente: ${s.name}`,
      kind: "source",
      sourcePublishedAt: s.source_published_at ?? null,
      observedAt: s.observed_at ?? null,
      url: s.url,
    });
  }
  const sig = ext.signals;
  if (sig.ssvc) {
    out.push({
      key: "ssvc",
      what: `SSVC: explotación ${sig.ssvc.exploitation ?? "?"}`,
      kind: "signal",
      sourcePublishedAt: sig.ssvc.source_published_at ?? null,
      observedAt: sig.ssvc.observed_at ?? null,
    });
  }
  sig.exploits.forEach((x, i) => {
    out.push({
      key: `exploit-${i}`,
      what: `Exploit${x.rule ? ` (${x.rule})` : ""}${x.origin ? ` · ${x.origin}` : ""}`,
      kind: "signal",
      sourcePublishedAt: x.source_published_at ?? null,
      observedAt: x.observed_at ?? null,
      url: x.url,
    });
  });
  if (sig.kev.cisa) {
    out.push({
      key: "kev",
      what: `Entra en CISA KEV${sig.kev.date_added ? ` (dateAdded ${sig.kev.date_added})` : ""}`,
      kind: "signal",
      // KEV solo publica una fecha (dateAdded), no una hora: no se usa como marca (PLAN.md §9).
      sourcePublishedAt: null,
      observedAt: sig.kev.observed_at ?? null,
    });
  }
  ext.level_history.forEach((h, i) => {
    out.push({
      key: `level-${i}`,
      what: `Nivel ${h.from} → ${h.level}${h.reason.length ? ` (${h.reason.join(", ")})` : ""}`,
      kind: "level",
      sourcePublishedAt: null,
      observedAt: h.at,
      level: h.level,
    });
  });
  ext.changes.forEach((c, i) => {
    out.push({
      key: `change-${i}`,
      what: `Publicado en el feed: ${changeLabel(c.type)}`,
      kind: "change",
      sourcePublishedAt: null,
      observedAt: c.at,
    });
  });
  return out.sort((a, b) => sortKey(a).localeCompare(sortKey(b)) || a.key.localeCompare(b.key));
}

/** Eventos OSV → texto legible: `>= 1.0.0, < 1.4.2`. */
export function describeEvents(events: { introduced?: string; fixed?: string; last_affected?: string; limit?: string }[]): string {
  const parts: string[] = [];
  let open: string | null = null;
  for (const e of events) {
    if (e.introduced !== undefined) {
      open = e.introduced === "0" ? "" : `>= ${e.introduced}`;
    } else if (e.fixed !== undefined) {
      parts.push([open, `< ${e.fixed}`].filter(Boolean).join(", "));
      open = null;
    } else if (e.last_affected !== undefined) {
      parts.push([open, `<= ${e.last_affected}`].filter(Boolean).join(", "));
      open = null;
    }
  }
  if (open !== null) parts.push(open || "todas las versiones");
  return parts.join(" · ") || "—";
}
