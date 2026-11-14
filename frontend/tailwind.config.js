/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        // Sin fuente externa a propósito: el laboratorio corre offline (ver
        // README), así que una fuente de Google Fonts se vería "bien" en
        // desarrollo y rota el día de la demo si no hay internet. Pila de
        // fuentes del sistema, cuidada por plataforma.
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: ["ui-monospace", "SFMono-Regular", "Consolas", "Menlo", "monospace"],
      },
      colors: {
        bg: "rgb(var(--color-bg) / <alpha-value>)",
        surface: "rgb(var(--color-surface) / <alpha-value>)",
        "surface-2": "rgb(var(--color-surface-2) / <alpha-value>)",
        "surface-hover": "rgb(var(--color-surface-hover) / <alpha-value>)",
        border: "rgb(var(--color-border) / <alpha-value>)",
        "border-strong": "rgb(var(--color-border-strong) / <alpha-value>)",
        ink: "rgb(var(--color-text) / <alpha-value>)",
        "ink-muted": "rgb(var(--color-text-muted) / <alpha-value>)",
        "ink-faint": "rgb(var(--color-text-faint) / <alpha-value>)",
        accent: "rgb(var(--color-accent) / <alpha-value>)",
        "accent-fg": "rgb(var(--color-accent-fg) / <alpha-value>)",
        danger: "rgb(var(--color-danger) / <alpha-value>)",
        warning: "rgb(var(--color-warning) / <alpha-value>)",
        ok: "rgb(var(--color-ok) / <alpha-value>)",
        // Alias de compatibilidad con el código existente (centinela-*).
        centinela: {
          bg: "rgb(var(--color-bg) / <alpha-value>)",
          panel: "rgb(var(--color-surface) / <alpha-value>)",
          accent: "rgb(var(--color-accent) / <alpha-value>)",
          danger: "rgb(var(--color-danger) / <alpha-value>)",
          warning: "rgb(var(--color-warning) / <alpha-value>)",
          ok: "rgb(var(--color-ok) / <alpha-value>)",
        },
      },
      boxShadow: {
        card: "0 1px 2px rgb(0 0 0 / 0.04), 0 8px 24px -8px rgb(0 0 0 / 0.20)",
        "card-dark": "0 1px 2px rgb(0 0 0 / 0.3), 0 12px 32px -8px rgb(0 0 0 / 0.55)",
        glow: "0 0 0 1px rgb(var(--color-accent) / 0.18), 0 8px 28px -6px rgb(var(--color-accent) / 0.35)",
      },
      keyframes: {
        "pulse-dot": {
          "0%, 100%": { opacity: 1, transform: "scale(1)" },
          "50%": { opacity: 0.55, transform: "scale(0.85)" },
        },
        "fade-in": {
          from: { opacity: 0, transform: "translateY(4px)" },
          to: { opacity: 1, transform: "translateY(0)" },
        },
      },
      animation: {
        "pulse-dot": "pulse-dot 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "fade-in": "fade-in 0.4s cubic-bezier(0.16, 1, 0.3, 1)",
      },
    },
  },
  plugins: [],
};
