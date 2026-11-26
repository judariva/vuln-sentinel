import { LockKeyhole } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

/**
 * Aviso visible de las pantallas restringidas (PLAN.md §10). En producción van detrás de
 * Cloudflare Access; en la v1 del portal muestran datos de ejemplo, no de la API.
 */
export function AccessNotice() {
  return (
    <Alert data-testid="access-notice" className="border-restricted bg-restricted text-restricted-foreground">
      <LockKeyhole aria-hidden="true" />
      <AlertTitle>Detrás de Access</AlertTitle>
      <AlertDescription className="text-restricted-foreground">
        Pantalla restringida: en producción solo se abre con una identidad autorizada por Cloudflare
        Access. Lo que ves son datos de ejemplo (fixture), no datos reales.
      </AlertDescription>
    </Alert>
  );
}
