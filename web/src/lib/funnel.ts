import type { ChangeEntry, LatestAlert } from "@/api/types";
import { ALERT_LEVELS, asLevel, type Level } from "@/theme/tokens";

/**
 * Datos del «embudo vivo» de Hoy. Todo sale de la API: cada CVE con cambios el día UTC del
 * `generated_at` en el feed completo (`all`) es una partícula, y su nivel es el ACTUAL (de
 * `latest.json` si es alerta; si no, el de su último cambio). Nada se inventa: si el feed no se
 * leyó entero (`complete` falso) la cifra es un mínimo y se dice.
 */

export interface FunnelParticle {
  id: string;
  level: Level;
}

export interface FunnelData {
  day: string;
  /** CVE distintas con cambios hoy en el feed completo. */
  total: number;
  counts: Record<Level, number>;
  /** Partículas que se dibujan (como mucho `MAX_PARTICLES`; las alertas, siempre). */
  particles: FunnelParticle[];
  /** Falso si quedaron páginas del feed sin leer: `total` es entonces un mínimo. */
  complete: boolean;
}

export const MAX_PARTICLES = 1500;

export function summarizeFunnel(
  generatedAt: string,
  entries: ChangeEntry[],
  latest: LatestAlert[],
  complete: boolean,
  max = MAX_PARTICLES,
): FunnelData {
  const day = generatedAt.slice(0, 10);
  const current = new Map(latest.map((a) => [a.id, asLevel(a.level)]));
  const last = new Map<string, ChangeEntry>();
  for (const e of entries) {
    if (!e.modified.startsWith(day)) continue;
    const prev = last.get(e.id);
    if (!prev || e.modified >= prev.modified) last.set(e.id, e);
  }
  const all: FunnelParticle[] = [...last.values()]
    .map((e) => ({ id: e.id, level: current.get(e.id) ?? asLevel(e.level) }))
    .sort((a, b) => a.id.localeCompare(b.id));
  const counts: Record<Level, number> = { A: 0, B: 0, C: 0, none: 0 };
  for (const p of all) counts[p.level] += 1;
  const alerts = all.filter((p) => p.level !== "none");
  const rest = all.filter((p) => p.level === "none");
  const particles = [...alerts, ...rest.slice(0, Math.max(0, max - alerts.length))];
  return { day, total: all.length, counts, particles, complete };
}

export function alertCount(data: Pick<FunnelData, "counts">): number {
  return ALERT_LEVELS.reduce((n, lv) => n + data.counts[lv], 0);
}

/** Hash estable (FNV-1a) de un id → [0, 1). Las posiciones de las partículas no son azar. */
export function unitHash(id: string, salt = 0): number {
  let h = 0x811c9dc5 ^ salt;
  for (let i = 0; i < id.length; i++) {
    h ^= id.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0) / 4294967296;
}
