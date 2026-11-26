/**
 * Cliente de la API pública (T6). El portal es un consumidor más (D10): solo `GET` sobre las rutas
 * públicas. La URL base sale de la configuración (ADR-0016).
 */

import { config } from "@/config";
import type { AlertsLatest, ChangeEntry, ChangesPage, MetricsDaily, VulnRecord } from "./types";

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** IDs de alerta estables (PLAN.md §3): `VS-CVE-AAAA-NNNN…`. */
export const ALERT_ID_RE = /^VS-CVE-\d{4}-\d{4,}$/;
const MAX_PAGES = 20;

export async function getJson<T>(path: string, signal?: AbortSignal, base = config.apiBaseUrl): Promise<T> {
  const resp = await fetch(`${base}${path}`, {
    method: "GET",
    headers: { Accept: "application/json" },
    credentials: "omit",
    signal,
  });
  if (!resp.ok) {
    throw new ApiError(resp.status, `La API respondió ${resp.status} en ${path}`);
  }
  return (await resp.json()) as T;
}

export function getAlertsLatest(signal?: AbortSignal) {
  return getJson<AlertsLatest>("/v1/feed/alerts/latest.json", signal);
}

/** Todo el índice «head» de un feed, siguiendo el cursor (como mucho `MAX_PAGES` páginas). */
export async function getAllChanges(
  feed: "all" | "alerts",
  signal?: AbortSignal,
): Promise<{ generatedAt: string; entries: ChangeEntry[] }> {
  const entries: ChangeEntry[] = [];
  let since: string | null = null;
  let generatedAt = "";
  for (let i = 0; i < MAX_PAGES; i++) {
    const q: string = since ? `?since=${encodeURIComponent(since)}` : "";
    const page: ChangesPage = await getJson<ChangesPage>(`/v1/feed/${feed}/changes${q}`, signal);
    generatedAt ||= page.generated_at;
    entries.push(...page.entries);
    if (!page.has_more || !page.next) break;
    since = page.next;
  }
  return { generatedAt, entries };
}

export function getVuln(id: string, signal?: AbortSignal) {
  if (!ALERT_ID_RE.test(id)) {
    return Promise.reject(new ApiError(404, `Identificador no válido: ${id}`));
  }
  return getJson<VulnRecord>(`/v1/vulns/${encodeURIComponent(id)}.json`, signal);
}

export function getMetricsDaily(signal?: AbortSignal) {
  return getJson<MetricsDaily>("/v1/metrics/daily.json", signal);
}
