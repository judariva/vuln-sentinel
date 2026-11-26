/**
 * Rejilla bento. Adaptado de Magic UI `bento-grid` (MIT, ver LICENSE-magicui.md).
 *
 * Cambios: colores del tema (`bg-card`, `border`), alto automático (las tarjetas llevan datos, no
 * ilustraciones), sin enlace ni `@radix-ui/react-icons`, y el título como encabezado real (`h2`).
 */
import type { ComponentPropsWithoutRef, ElementType, ReactNode } from "react";
import { cn } from "@/lib/utils";

interface BentoGridProps extends ComponentPropsWithoutRef<"div"> {
  children: ReactNode;
}

export function BentoGrid({ children, className, ...props }: BentoGridProps) {
  return (
    <div className={cn("grid w-full grid-cols-1 gap-4 md:grid-cols-3", className)} {...props}>
      {children}
    </div>
  );
}

interface BentoCardProps extends Omit<ComponentPropsWithoutRef<"section">, "title"> {
  name: ReactNode;
  description?: ReactNode;
  Icon?: ElementType;
  /** Id del encabezado, para `aria-labelledby`. */
  headingId: string;
  children?: ReactNode;
}

export function BentoCard({ name, description, Icon, headingId, children, className, ...props }: BentoCardProps) {
  return (
    <section
      aria-labelledby={headingId}
      className={cn(
        "group relative col-span-1 flex flex-col overflow-hidden rounded-xl border bg-card text-card-foreground shadow-sm",
        "transform-gpu transition-shadow duration-300 hover:shadow-md",
        className,
      )}
      {...props}
    >
      <div className="flex flex-col gap-1 p-4 pb-2">
        <h2 id={headingId} className="flex items-center gap-2 font-semibold leading-none">
          {Icon ? (
            <Icon
              aria-hidden="true"
              className="size-4 origin-left text-muted-foreground transition-transform duration-300 group-hover:scale-110"
            />
          ) : null}
          {name}
        </h2>
        {description ? <p className="text-sm text-muted-foreground">{description}</p> : null}
      </div>
      <div className="flex-1 px-4 pb-4">{children}</div>
    </section>
  );
}
