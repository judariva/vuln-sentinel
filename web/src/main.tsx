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

createRoot(root).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
);
