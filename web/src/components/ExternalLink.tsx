import type { ReactNode } from "react";
import { safeUrl } from "@/lib/format";

/** Enlace a una fuente externa: solo https; si no, se muestra como texto sin enlace. */
export function ExternalLink({ href, children }: { href: string | null | undefined; children?: ReactNode }) {
  const url = safeUrl(href);
  const text = children ?? href ?? "—";
  if (!url) return <span className="break-all">{text}</span>;
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer nofollow"
      className="break-all text-foreground underline underline-offset-4 hover:text-muted-foreground"
    >
      {text}
    </a>
  );
}
