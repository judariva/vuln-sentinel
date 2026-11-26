/** Datos de prueba de los tests de componentes. Todo ficticio (CVE-2099-*, hosts `.invalid`). */
import type { ChangesPage, AlertsLatest, MetricsDaily, VulnRecord } from "@/api/types";

export const DAY = "2099-03-01";

export const CHANGES: ChangesPage = {
  schema_version: "1.0.0",
  kind: "changes",
  feed: "alerts",
  generated_at: `${DAY}T18:00:00Z`,
  entries: [
    { id: "VS-CVE-2099-0001", modified: "2099-02-28T23:00:00Z", level: "C", type: "new", sha256: "a".repeat(64) },
    { id: "VS-CVE-2099-1001", modified: `${DAY}T13:05:00Z`, level: "C", type: "new", sha256: "b".repeat(64) },
    { id: "VS-CVE-2099-1001", modified: `${DAY}T15:05:00Z`, level: "B", type: "level_up", sha256: "c".repeat(64) },
    { id: "VS-CVE-2099-1001", modified: `${DAY}T16:05:00Z`, level: "A", type: "level_up", sha256: "d".repeat(64) },
    { id: "VS-CVE-2099-1004", modified: `${DAY}T13:05:00Z`, level: "C", type: "new", sha256: "e".repeat(64) },
  ],
  next: null,
  has_more: false,
};

export const LATEST: AlertsLatest = {
  generated_at: `${DAY}T18:00:00Z`,
  alerts: [
    { id: "VS-CVE-2099-1001", modified: `${DAY}T16:05:00Z`, level: "A", sha256: "d".repeat(64) },
    { id: "VS-CVE-2099-1004", modified: `${DAY}T13:05:00Z`, level: "C", sha256: "e".repeat(64) },
    { id: "VS-CVE-2099-0001", modified: "2099-02-28T23:00:00Z", level: "C", sha256: "a".repeat(64) },
  ],
};

export const RECORD: VulnRecord = {
  id: "VS-CVE-2099-1001",
  aliases: ["CVE-2099-1001"],
  published: `${DAY}T13:05:00Z`,
  modified: `${DAY}T16:05:00Z`,
  affected: [
    {
      ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.4.2" }, { introduced: "1.5.0" }, { fixed: "1.5.3" }] }],
      database_specific: {
        source: "cvelistv5",
        range_source: "cna:example-cna",
        vendor: "Examplesoft",
        product: "Exampled",
        cpe: ["cpe:2.3:a:examplesoft:exampled:*:*:*:*:*:*:*:*"],
      },
    },
  ],
  references: [{ type: "ADVISORY", url: "https://advisory.example.invalid/x" }],
  database_specific: {
    vuln_sentinel: {
      level: "A",
      impact_class: "rce",
      level_reason: ["A.kev_cisa"],
      level_history: [
        { level: "C", from: "none", at: `${DAY}T13:05:00Z`, reason: ["C.rce_unauth"] },
        { level: "B", from: "C", at: `${DAY}T15:05:00Z`, reason: ["B.exploit:E1"] },
        { level: "A", from: "B", at: `${DAY}T16:05:00Z`, reason: ["A.kev_cisa"] },
      ],
      cwe: ["CWE-787"],
      signals: {
        kev: { cisa: true, date_added: DAY, observed_at: `${DAY}T16:05:00Z` },
        ssvc: { exploitation: "none", automatable: "yes", technical_impact: "total", source_published_at: `${DAY}T12:00:00Z`, observed_at: `${DAY}T13:05:00Z` },
        exploits: [
          { rule: "E1", status: "trusted", origin: "metasploit", url: "javascript:alert(1)", source_published_at: `${DAY}T14:30:00Z`, observed_at: `${DAY}T15:05:00Z` },
        ],
        fix: { available: true, versions: ["1.4.2", "1.5.3"] },
      },
      sources: [{ name: "cvelistv5", url: "https://cve.example.invalid/CVE-2099-1001", source_published_at: `${DAY}T12:05:00Z`, observed_at: `${DAY}T13:05:00Z` }],
      changes: [
        { type: "new", at: `${DAY}T13:05:00Z` },
        { type: "level_up", at: `${DAY}T15:05:00Z`, level_from: "C", level_to: "B" },
        { type: "level_up", at: `${DAY}T16:05:00Z`, level_from: "B", level_to: "A" },
      ],
      ai: { used: false },
    },
  },
};

export const METRICS: MetricsDaily = {
  from: "2099-02-27",
  to: "2099-02-28",
  rows: [
    { day: "2099-02-27", metric: "funnel.ingested", dimension: "", value: 500 },
    { day: "2099-02-28", metric: "funnel.ingested", dimension: "", value: 600 },
    { day: "2099-02-28", metric: "funnel.eligible", dimension: "", value: 70 },
    { day: "2099-02-28", metric: "funnel.candidate", dimension: "", value: 8 },
    { day: "2099-02-28", metric: "funnel.alerted", dimension: "A", value: 1 },
    { day: "2099-02-28", metric: "funnel.alerted", dimension: "C", value: 2 },
    { day: "2099-02-27", metric: "detection.p50_minutes", dimension: "A", value: 99 },
    { day: "2099-02-28", metric: "detection.p50_minutes", dimension: "A", value: 35 },
    { day: "2099-02-28", metric: "detection.p95_minutes", dimension: "A", value: 140 },
    { day: "2099-02-28", metric: "kev_lead.p50_minutes", dimension: "", value: 600 },
    { day: "2099-02-28", metric: "changes.by_type", dimension: "new", value: 600 },
    { day: "2099-02-28", metric: "changes.by_type", dimension: "kev_added", value: 1 },
  ],
};

/** `fetch` falso que responde por ruta. Registra las URL pedidas. */
export function fakeFetch(routes: Record<string, unknown>, calls: string[] = []) {
  return async (input: RequestInfo | URL): Promise<Response> => {
    const url = String(input);
    calls.push(url);
    const path = url.replace(/^https?:\/\/[^/]+/, "").split("?")[0];
    if (path in routes) {
      return new Response(JSON.stringify(routes[path]), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ error: "not_found" }), { status: 404 });
  };
}
