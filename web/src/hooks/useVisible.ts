import { useEffect, useState, type RefObject } from "react";

/**
 * ¿Ha entrado ya el elemento en pantalla (o cerca, `rootMargin`)? Una vez visible, se queda en
 * verdadero. Sin `IntersectionObserver` (jsdom, navegadores viejos) es verdadero desde el principio:
 * nunca se esconde un dato por no poder medir.
 */
export function useVisible(ref: RefObject<Element | null>, rootMargin = "200px"): boolean {
  const supported = typeof IntersectionObserver !== "undefined";
  const [visible, setVisible] = useState(!supported);
  useEffect(() => {
    if (!supported || visible || !ref.current) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setVisible(true);
          io.disconnect();
        }
      },
      { rootMargin },
    );
    io.observe(ref.current);
    return () => io.disconnect();
  }, [ref, rootMargin, supported, visible]);
  return visible;
}
