import { startTransition, useEffect, useRef, useState } from "react";

export type ApiState<T> =
  | { status: "loading" }
  | { status: "error"; error: Error }
  | { status: "ok"; data: T };

interface Stored<T> {
  key: string;
  state: ApiState<T>;
}

/**
 * Carga un documento de la API. `key` identifica la petición: si cambia, se vuelve a pedir y se
 * aborta la anterior. El estado «cargando» se deriva de la clave, sin setState síncrono.
 *
 * Con `refreshMs`, se vuelve a pedir cada tanto sin pasar por «cargando»: los datos anteriores
 * siguen en pantalla hasta que llegan los nuevos (así se ven los cambios de nivel). Si un refresco
 * falla, se muestra el error: nunca se dejan datos viejos como si fueran actuales (fail-closed).
 */
export function useApi<T>(
  key: string,
  load: (signal: AbortSignal) => Promise<T>,
  refreshMs?: number,
): ApiState<T> {
  const loader = useRef(load);
  useEffect(() => {
    loader.current = load;
  });
  const [stored, setStored] = useState<Stored<T> | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (!refreshMs) return;
    const id = setInterval(() => setTick((n) => n + 1), refreshMs);
    return () => clearInterval(id);
  }, [refreshMs]);

  useEffect(() => {
    const ctrl = new AbortController();
    loader
      .current(ctrl.signal)
      // En una transición: React pinta los datos a trozos y no bloquea el hilo principal (T8b).
      .then((data) => startTransition(() => setStored({ key, state: { status: "ok", data } })))
      .catch((error: unknown) => {
        if (ctrl.signal.aborted) return;
        const err = error instanceof Error ? error : new Error(String(error));
        setStored({ key, state: { status: "error", error: err } });
      });
    return () => ctrl.abort();
  }, [key, tick]);

  return stored && stored.key === key ? stored.state : { status: "loading" };
}
