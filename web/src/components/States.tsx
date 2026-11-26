import { AlertTriangle } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";

export function Loading({ label = "Cargando…" }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" className="space-y-3">
      <span className="sr-only">{label}</span>
      <Skeleton className="h-8 w-1/3" />
      <Skeleton className="h-32 w-full" />
    </div>
  );
}

/** Fail-closed también en el portal: si la API falla, se dice; nunca «sin novedades». */
export function LoadError({ error }: { error: Error }) {
  return (
    <Alert variant="destructive" role="alert">
      <AlertTriangle aria-hidden="true" />
      <AlertTitle>No se pudo leer la API</AlertTitle>
      <AlertDescription>
        {error.message}. Esto no significa que no haya alertas: el estado es desconocido.
      </AlertDescription>
    </Alert>
  );
}
