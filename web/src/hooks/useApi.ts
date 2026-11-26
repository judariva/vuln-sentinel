import { useEffect, useRef, useState } from "react";

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
 */
export function useApi<T>(key: string, load: (signal: AbortSignal) => Promise<T>): ApiState<T> {
  const loader = useRef(load);
  useEffect(() => {
    loader.current = load;
  });
  const [stored, setStored] = useState<Stored<T> | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    loader
      .current(ctrl.signal)
      .then((data) => setStored({ key, state: { status: "ok", data } }))
      .catch((error: unknown) => {
        if (ctrl.signal.aborted) return;
        const err = error instanceof Error ? error : new Error(String(error));
        setStored({ key, state: { status: "error", error: err } });
      });
    return () => ctrl.abort();
  }, [key]);

  return stored && stored.key === key ? stored.state : { status: "loading" };
}
