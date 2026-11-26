import type { ChangeEntry, LatestAlert } from "@/api/types";
import { ALERT_LEVELS, asLevel, type Level } from "@/theme/tokens";

export interface TodayAlert {
  id: string;
  level: Level;
  types: string[];
  lastChange: string;
}

export interface TodaySummary {
  day: string;
  byLevel: Record<"A" | "B" | "C", TodayAlert[]>;
  changes: ChangeEntry[];
}

/**
 * Alertas del día (UTC del `generated_at` de la API) agrupadas por nivel ACTUAL, con los tipos de
 * cambio del día. El nivel sale de `latest.json` (estado actual); si falta, del último cambio.
 */
export function summarizeToday(
  generatedAt: string,
  entries: ChangeEntry[],
  latest: LatestAlert[],
): TodaySummary {
  const day = generatedAt.slice(0, 10);
  const current = new Map(latest.map((a) => [a.id, asLevel(a.level)]));
  const changes = entries
    .filter((e) => e.modified.startsWith(day))
    .sort((a, b) => b.modified.localeCompare(a.modified) || a.id.localeCompare(b.id));
  const acc = new Map<string, TodayAlert>();
  for (const e of [...changes].reverse()) {
    const item = acc.get(e.id) ?? { id: e.id, level: "none" as Level, types: [], lastChange: e.modified };
    if (!item.types.includes(e.type)) item.types.push(e.type);
    item.lastChange = e.modified;
    item.level = current.get(e.id) ?? asLevel(e.level);
    acc.set(e.id, item);
  }
  const byLevel = { A: [], B: [], C: [] } as TodaySummary["byLevel"];
  for (const item of acc.values()) {
    if (item.level !== "none") byLevel[item.level].push(item);
  }
  for (const lv of ALERT_LEVELS) byLevel[lv].sort((a, b) => b.lastChange.localeCompare(a.lastChange));
  return { day, byLevel, changes };
}
