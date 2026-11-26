/** Tipos de los documentos de la API pública (T6, PLAN.md §3). Solo lo que usa el portal. */

export type LevelLabel = "A" | "B" | "C" | "none";

export interface ChangeEntry {
  id: string;
  modified: string;
  level: LevelLabel;
  type: string;
  sha256: string;
}

export interface ChangesPage {
  schema_version: string;
  kind: "changes";
  feed: "all" | "alerts";
  generated_at: string;
  entries: ChangeEntry[];
  next: string | null;
  has_more: boolean;
}

export interface LatestAlert {
  id: string;
  modified: string;
  level: LevelLabel;
  sha256: string;
}

export interface AlertsLatest {
  generated_at: string;
  alerts: LatestAlert[];
}

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface Affected {
  package?: { ecosystem: string; name: string; purl?: string };
  ranges?: { type: string; events: OsvEvent[]; repo?: string }[];
  versions?: string[];
  database_specific?: {
    source?: string;
    range_source?: string | null;
    vendor?: string;
    product?: string;
    cpe?: string[];
    purl?: string;
  };
}

export interface Stamped {
  source_published_at?: string | null;
  observed_at?: string | null;
}

export interface ExploitSignal extends Stamped {
  rule: string | null;
  status?: string;
  origin?: string | null;
  url: string | null;
}

export interface Signals {
  kev: { cisa: boolean; date_added?: string | null; observed_at?: string | null };
  ssvc?: { exploitation?: string; automatable?: string; technical_impact?: string } & Stamped;
  epss?: { score: number | null; percentile: number | null; model?: string; date?: string; delta_7d?: number | null };
  exploits: ExploitSignal[];
  fix: { available: boolean; versions: string[] };
  vendor_exploited?: { url: string; observed_at: string }[];
  mitigation?: { text: string; url?: string }[];
}

export interface SourceRef extends Stamped {
  name: string;
  url: string | null;
}

export interface LevelHistoryItem {
  level: LevelLabel;
  from: LevelLabel;
  at: string;
  reason: string[];
  decided_by?: string;
}

export interface ChangeItem {
  type: string;
  at: string;
  level_from?: LevelLabel;
  level_to?: LevelLabel;
}

export interface VulnRecord {
  id: string;
  aliases?: string[];
  published: string;
  modified: string;
  withdrawn?: string;
  summary?: string;
  severity?: { type: string; score: string }[];
  affected?: Affected[];
  references?: { type: string; url: string }[];
  database_specific: {
    vuln_sentinel: {
      level: LevelLabel;
      impact_class: string;
      level_reason: string[];
      level_history: LevelHistoryItem[];
      cwe?: string[];
      signals: Signals;
      sources: SourceRef[];
      changes: ChangeItem[];
      ai: { used: boolean; dossier?: unknown };
    };
  };
}

export interface MetricRow {
  day: string;
  metric: string;
  dimension: string;
  value: number;
}

export interface MetricsDaily {
  from: string;
  to: string;
  rows: MetricRow[];
}
