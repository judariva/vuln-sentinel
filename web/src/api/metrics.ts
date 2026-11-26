/**
 * Nombres de `metric_daily` que lee la pantalla de Métricas y cómo se agregan (PLAN.md §9).
 *
 * T6 solo fijó `cost.eur` y `donations.*`. Los demás nombres son una PROPUESTA (pregunta abierta de
 * T6 y T8a): si `job-daily` los escribe con otro nombre, solo cambia este fichero.
 */

import type { MetricRow } from "./types";
import { ALERT_LEVELS } from "@/theme/tokens";

export const METRIC = {
  ingested: "funnel.ingested",
  eligible: "funnel.eligible",
  candidate: "funnel.candidate",
  alerted: "funnel.alerted", // dimension = nivel
  detectionP50: "detection.p50_minutes", // dimension = nivel
  detectionP95: "detection.p95_minutes", // dimension = nivel
  kevLead: "kev_lead.p50_minutes", // positivo = antes que KEV
  changesByType: "changes.by_type", // dimension = tipo de cambio
} as const;

function sum(rows: MetricRow[], metric: string, dimension?: string): number {
  return rows
    .filter((r) => r.metric === metric && (dimension === undefined || r.dimension === dimension))
    .reduce((acc, r) => acc + r.value, 0);
}

export interface FunnelStep {
  step: string;
  value: number;
}

export function funnel(rows: MetricRow[]): FunnelStep[] {
  return [
    { step: "Ingeridas", value: sum(rows, METRIC.ingested) },
    { step: "Elegibles", value: sum(rows, METRIC.eligible) },
    { step: "Candidatas", value: sum(rows, METRIC.candidate) },
    { step: "A, B o C", value: sum(rows, METRIC.alerted) },
  ];
}

export interface AlertsPerDay {
  day: string;
  A: number;
  B: number;
  C: number;
}

export function alertsPerDay(rows: MetricRow[]): AlertsPerDay[] {
  const days = [...new Set(rows.filter((r) => r.metric === METRIC.alerted).map((r) => r.day))].sort();
  return days.map((day) => {
    const ofDay = rows.filter((r) => r.day === day);
    return { day, A: sum(ofDay, METRIC.alerted, "A"), B: sum(ofDay, METRIC.alerted, "B"), C: sum(ofDay, METRIC.alerted, "C") };
  });
}

export interface DetectionByLevel {
  level: string;
  p50: number | null;
  p95: number | null;
}

/** p50 y p95 del ÚLTIMO día con datos (los percentiles diarios no se promedian). */
export function detection(rows: MetricRow[]): { day: string | null; byLevel: DetectionByLevel[] } {
  const days = rows.filter((r) => r.metric === METRIC.detectionP50).map((r) => r.day).sort();
  const day = days.at(-1) ?? null;
  const pick = (metric: string, level: string) =>
    rows.find((r) => r.day === day && r.metric === metric && r.dimension === level)?.value ?? null;
  return {
    day,
    byLevel: ALERT_LEVELS.map((level) => ({
      level,
      p50: pick(METRIC.detectionP50, level),
      p95: pick(METRIC.detectionP95, level),
    })),
  };
}

export function kevLead(rows: MetricRow[]): { day: string; hours: number }[] {
  return rows
    .filter((r) => r.metric === METRIC.kevLead)
    .sort((a, b) => a.day.localeCompare(b.day))
    .map((r) => ({ day: r.day, hours: Math.round((r.value / 60) * 10) / 10 }));
}

export function changesByType(rows: MetricRow[]): { type: string; value: number }[] {
  const types = [...new Set(rows.filter((r) => r.metric === METRIC.changesByType).map((r) => r.dimension))];
  return types
    .map((type) => ({ type, value: sum(rows, METRIC.changesByType, type) }))
    .sort((a, b) => b.value - a.value);
}
