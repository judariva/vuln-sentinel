/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** URL base de la API pública (ADR-0016). Vacía = mismo origen que el portal. */
  readonly VITE_API_BASE_URL?: string;
  /** Nombre del producto que se muestra (ADR-0016). */
  readonly VITE_BRAND_NAME?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
