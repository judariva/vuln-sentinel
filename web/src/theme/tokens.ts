/**
 * Puente entre `tokens.css` (los VALORES) y el código. Aquí no hay ningún color: solo los nombres de
 * las variables y de las clases de Tailwind que salen de ellas. Así los colores de A, B y C son los
 * mismos en todo el portal (insignias, gráficas, línea de tiempo).
 */

export type Level = "A" | "B" | "C" | "none";
export const ALERT_LEVELS = ["A", "B", "C"] as const;

/** Color de cada nivel para SVG y estilos en línea (Recharts). */
export const levelColor: Record<Level, string> = {
  A: "var(--level-a)",
  B: "var(--level-b)",
  C: "var(--level-c)",
  none: "var(--level-none)",
};

/** Clases de Tailwind (fondo + texto con contraste suficiente) de cada nivel. */
export const levelClass: Record<Level, string> = {
  A: "bg-level-a text-level-foreground",
  B: "bg-level-b text-level-foreground",
  C: "bg-level-c text-level-foreground",
  none: "bg-level-none text-level-foreground",
};

export const levelLabel: Record<Level, string> = {
  A: "Nivel A · explotación activa",
  B: "Nivel B · exploit público",
  C: "Nivel C · RCE sin exploit",
  none: "Sin nivel",
};

export function asLevel(raw: unknown): Level {
  return raw === "A" || raw === "B" || raw === "C" ? raw : "none";
}

/** Series de gráficas que no son niveles. */
export const chartColor = ["var(--chart-1)", "var(--chart-2)", "var(--chart-3)", "var(--chart-4)", "var(--chart-5)"];

// -- tema -------------------------------------------------------------------------------------------

export type Theme = "dark" | "light";
export const THEME_KEY = "vs-theme";
export const DEFAULT_THEME: Theme = "dark";

export function storedTheme(storage: Pick<Storage, "getItem"> | undefined): Theme {
  const v = storage?.getItem(THEME_KEY);
  return v === "light" || v === "dark" ? v : DEFAULT_THEME;
}

export function applyTheme(theme: Theme, root: HTMLElement = document.documentElement): void {
  root.classList.toggle("dark", theme === "dark");
  root.style.colorScheme = theme;
}
