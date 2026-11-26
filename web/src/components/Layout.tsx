import { LockKeyhole, Moon, Sun } from "lucide-react";
import * as m from "motion/react-m";
import { useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { config } from "@/config";
import { cn } from "@/lib/utils";
import { PATHS } from "@/routes";
import { applyTheme, storedTheme, THEME_KEY, type Theme } from "@/theme/tokens";

const NAV: { to: string; label: string; restricted?: boolean }[] = [
  { to: PATHS.today, label: "Hoy" },
  { to: PATHS.metrics, label: "Métricas" },
  { to: PATHS.sources, label: "Fuentes", restricted: true },
  { to: PATHS.admin, label: "Administración", restricted: true },
];

function safeStorage(): Storage | undefined {
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(() => storedTheme(safeStorage()));
  const next: Theme = theme === "dark" ? "light" : "dark";
  return (
    <Button
      variant="outline"
      size="sm"
      aria-label={next === "light" ? "Cambiar a tema claro" : "Cambiar a tema oscuro"}
      onClick={() => {
        applyTheme(next);
        safeStorage()?.setItem(THEME_KEY, next);
        setTheme(next);
      }}
    >
      {next === "light" ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}
      {next === "light" ? "Claro" : "Oscuro"}
    </Button>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const location = useLocation();
  return (
    <div className="min-h-screen">
      <a href="#contenido" className="sr-only focus:not-sr-only focus:absolute focus:p-2">
        Saltar al contenido
      </a>
      <header className="mx-auto flex max-w-6xl flex-wrap items-center gap-4 px-4 py-4">
        <p className="text-lg font-semibold tracking-tight">{config.brandName}</p>
        <nav aria-label="Principal" className="flex flex-1 flex-wrap gap-1">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                cn(
                  "inline-flex items-center gap-1 rounded-md px-3 py-1.5 text-sm",
                  isActive ? "bg-secondary text-secondary-foreground" : "text-muted-foreground hover:text-foreground",
                )
              }
            >
              {item.label}
              {item.restricted ? (
                <>
                  <LockKeyhole className="size-3" aria-hidden="true" />
                  <span className="sr-only">(detrás de Access)</span>
                </>
              ) : null}
            </NavLink>
          ))}
        </nav>
        <ThemeToggle />
      </header>
      <Separator />
      <main id="contenido" className="mx-auto max-w-6xl space-y-6 px-4 py-6">
        {/*
          Transición entre pantallas: solo desplazamiento, sin opacidad (axe mediría el contraste
          de un texto a medio aparecer). Con `prefers-reduced-motion`, nada (MotionConfig).
        */}
        <m.div
          key={location.pathname}
          initial={{ y: 10 }}
          animate={{ y: 0 }}
          transition={{ type: "spring", stiffness: 300, damping: 30 }}
        >
          {children}
        </m.div>
      </main>
    </div>
  );
}
