/**
 * Rutas del portal y prefijos que son de la API (T6).
 *
 * El portal y la API pueden servirse en el mismo origen (la prueba de humo lo hace, y es una de
 * las opciones de despliegue). Si una ruta del portal empieza por un prefijo de la API, la petición
 * llega a la API y no al portal: `/admin` respondía el 403 de Access en vez de la pantalla. Por eso
 * ninguna ruta del portal empieza, ni como cadena, por un prefijo de la API: así tampoco la captura
 * una regla con comodín del tipo `/admin*` (lo comprueba `test/routes.test.ts`).
 */
export const PATHS = {
  today: "/",
  detail: "/alertas",
  metrics: "/metricas",
  sources: "/fuentes",
  admin: "/gestion",
} as const;

/** Prefijos de la API pública y de administración (src/vs/api/app.py). */
export const API_PREFIXES = ["/v1", "/.well-known", "/admin"] as const;

/** ¿La ruta del portal cae, como cadena, en el espacio de la API? */
export function collidesWithApi(path: string): boolean {
  return API_PREFIXES.some((p) => path.startsWith(p));
}
