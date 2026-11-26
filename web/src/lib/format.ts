/** Formato de fechas (siempre UTC, como el feed) y enlaces seguros. */

/** `2099-03-01T13:05:00Z` → `2099-03-01 13:05 UTC`. Sin dato → `—`. */
export function utc(ts: string | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "—";
  return `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export function utcTime(ts: string | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? "—" : d.toISOString().slice(11, 16);
}

/**
 * Solo enlaces https: los datos del feed vienen de fuentes de terceros y un `javascript:` o un
 * `data:` no puede llegar a un `href`. Devuelve null si el enlace no es seguro.
 */
export function safeUrl(raw: string | null | undefined): string | null {
  if (!raw) return null;
  try {
    const url = new URL(raw);
    return url.protocol === "https:" ? url.toString() : null;
  } catch {
    return null;
  }
}

export const CHANGE_LABEL: Record<string, string> = {
  new: "nueva",
  level_up: "sube de nivel",
  kev_added: "entra en KEV",
  poc_added: "exploit publicado",
  fix_released: "parche publicado",
  epss_jump: "salto de EPSS",
  range_completed: "rangos completos",
  withdrawn: "retirada",
  updated: "actualizada",
};

export function changeLabel(type: string): string {
  return CHANGE_LABEL[type] ?? type;
}
