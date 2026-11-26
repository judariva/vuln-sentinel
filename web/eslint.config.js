import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "node_modules", "test-results", "playwright-report"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2023,
      globals: { ...globals.browser, ...globals.node },
    },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Ningún host escrito a mano (ADR-0016): las URL salen de VITE_*.
      "no-restricted-syntax": [
        "error",
        {
          selector: "Literal[value=/^https?:\\/\\/(?!127\\.0\\.0\\.1|localhost)/]",
          message: "Nada de URL escritas a mano: van en configuración (ADR-0016).",
        },
      ],
    },
  },
  {
    // Los tests usan URL ficticias (`.invalid`) para comprobar los enlaces.
    files: ["src/**/*.test.{ts,tsx}", "src/test/**", "e2e/**"],
    rules: { "no-restricted-syntax": "off" },
  },
);
