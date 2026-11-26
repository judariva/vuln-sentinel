import { domAnimation, LazyMotion, MotionConfig } from "motion/react";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { App } from "@/App";
import { config } from "@/config";
import { applyTheme, storedTheme } from "@/theme/tokens";
import "./index.css";

function storage(): Storage | undefined {
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}

applyTheme(storedTheme(storage()));
document.title = config.brandName;

const root = document.getElementById("root");
if (!root) throw new Error("falta #root");

// Motion (T8b): `LazyMotion` con `domAnimation` y componentes `m` (menos JS inicial; `strict` impide
// colar un `motion.*` completo). `reducedMotion="user"`: con `prefers-reduced-motion` no se anima.
createRoot(root).render(
  <StrictMode>
    <LazyMotion features={domAnimation} strict>
      <MotionConfig reducedMotion="user">
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </MotionConfig>
    </LazyMotion>
  </StrictMode>,
);
