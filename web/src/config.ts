/**
 * Configuración del portal (ADR-0016): hosts, URL base y marca salen SOLO de variables `VITE_*`
 * inyectadas en el build del despliegue. Aquí no se escribe ningún host ni ningún nombre de marca.
 */

export interface PortalConfig {
  /** Sin barra final. Vacía = la API se sirve en el mismo origen que el portal. */
  apiBaseUrl: string;
  /** Nombre que se muestra. Si falta, un rótulo genérico (no es la marca). */
  brandName: string;
}

const GENERIC_NAME = "Monitor de vulnerabilidades";

export class ConfigError extends Error {}

export function readConfig(env: Record<string, string | undefined>): PortalConfig {
  const raw = (env.VITE_API_BASE_URL ?? "").trim();
  if (raw !== "") {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new ConfigError("VITE_API_BASE_URL no es una URL válida");
    }
    // Solo https; http únicamente para pruebas locales.
    const local = url.hostname === "127.0.0.1" || url.hostname === "localhost";
    if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
      throw new ConfigError("VITE_API_BASE_URL debe ser https");
    }
  }
  return {
    apiBaseUrl: raw.replace(/\/+$/, ""),
    brandName: (env.VITE_BRAND_NAME ?? "").trim() || GENERIC_NAME,
  };
}

export const config: PortalConfig = readConfig(import.meta.env);
