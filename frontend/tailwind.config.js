/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        centinela: {
          bg: "#0b1120",
          panel: "#111827",
          accent: "#38bdf8",
          danger: "#f87171",
          warning: "#fbbf24",
          ok: "#4ade80",
        },
      },
    },
  },
  plugins: [],
};
