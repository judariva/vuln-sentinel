/**
 * Datos de EJEMPLO de las pantallas restringidas (Fuentes y Administración). No salen de la API:
 * en la v1 esas rutas de la API son un esqueleto detrás de Access (T6, `/admin` → 501).
 * Todo es ficticio: CVE-2099-*, trazas inventadas, ninguna identidad real.
 */

export type RunStatus = "ok" | "partial" | "unknown";

export interface SourceHealth {
  name: string;
  status: RunStatus;
  lastRunAt: string;
  lastItemPublishedAt: string | null;
  itemsSeen: number;
  itemsNew: number;
  freshnessMinutes: number;
  error?: string;
}

export const SOURCES: SourceHealth[] = [
  { name: "cvelistv5", status: "ok", lastRunAt: "2099-03-01T17:55:00Z", lastItemPublishedAt: "2099-03-01T17:41:00Z", itemsSeen: 412, itemsNew: 23, freshnessMinutes: 15 },
  { name: "cisa-kev", status: "ok", lastRunAt: "2099-03-01T17:50:00Z", lastItemPublishedAt: "2099-03-01T16:05:00Z", itemsSeen: 1, itemsNew: 1, freshnessMinutes: 15 },
  { name: "epss", status: "ok", lastRunAt: "2099-03-01T06:10:00Z", lastItemPublishedAt: "2099-03-01T00:00:00Z", itemsSeen: 280114, itemsNew: 0, freshnessMinutes: 1440 },
  { name: "ghsa", status: "partial", lastRunAt: "2099-03-01T17:45:00Z", lastItemPublishedAt: "2099-03-01T17:12:00Z", itemsSeen: 37, itemsNew: 4, freshnessMinutes: 30, error: "página 3 sin leer (HTTP 502)" },
  { name: "osv", status: "ok", lastRunAt: "2099-03-01T17:40:00Z", lastItemPublishedAt: "2099-03-01T17:20:00Z", itemsSeen: 96, itemsNew: 9, freshnessMinutes: 30 },
  { name: "exploits", status: "unknown", lastRunAt: "2099-03-01T17:30:00Z", lastItemPublishedAt: null, itemsSeen: 0, itemsNew: 0, freshnessMinutes: 60, error: "timeout: fuente caída, sin datos (fail-closed)" },
];

export interface ApprovalItem {
  alertId: string;
  level: "A" | "B" | "C";
  channel: "x" | "linkedin";
  requestedAt: string;
}

export const APPROVALS: ApprovalItem[] = [
  { alertId: "VS-CVE-2099-1001", level: "A", channel: "x", requestedAt: "2099-03-01T16:06:00Z" },
  { alertId: "VS-CVE-2099-1001", level: "A", channel: "linkedin", requestedAt: "2099-03-01T16:06:00Z" },
  { alertId: "VS-CVE-2099-1005", level: "B", channel: "x", requestedAt: "2099-03-01T15:06:00Z" },
];

export interface VerdictItem {
  alertId: string;
  verdict: "useful" | "noise" | null;
}

export const VERDICTS: VerdictItem[] = [
  { alertId: "VS-CVE-2099-1001", verdict: "useful" },
  { alertId: "VS-CVE-2099-1005", verdict: null },
  { alertId: "VS-CVE-2099-1004", verdict: null },
];

export interface AiCost {
  day: string;
  calls: number;
  costUsd: number;
  blockedDowngrades: number;
}

export const AI_COST: AiCost[] = [
  { day: "2099-02-27", calls: 4, costUsd: 0.31, blockedDowngrades: 0 },
  { day: "2099-02-28", calls: 6, costUsd: 0.52, blockedDowngrades: 1 },
  { day: "2099-03-01", calls: 3, costUsd: 0.27, blockedDowngrades: 0 },
];

export interface TraceItem {
  traceId: string;
  alertId: string;
  kind: "investigate" | "draft";
  steps: number;
  outcome: "confirmed" | "blocked_downgrade" | "no_change";
}

export const TRACES: TraceItem[] = [
  { traceId: "trace-example-0001", alertId: "VS-CVE-2099-1005", kind: "investigate", steps: 7, outcome: "confirmed" },
  { traceId: "trace-example-0002", alertId: "VS-CVE-2099-1004", kind: "investigate", steps: 5, outcome: "blocked_downgrade" },
  { traceId: "trace-example-0003", alertId: "VS-CVE-2099-1005", kind: "draft", steps: 1, outcome: "no_change" },
];
