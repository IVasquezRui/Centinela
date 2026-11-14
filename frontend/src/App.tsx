import { NavLink, Route, Routes } from "react-router-dom";

import ThemeToggle from "./components/ThemeToggle";
import Observatorio from "./pages/Observatorio";
import Soc from "./pages/Soc";

function SentinelMark() {
  return (
    <svg viewBox="0 0 32 32" className="h-7 w-7 shrink-0" aria-hidden="true">
      <path
        d="M16 2.5 27 7v8.2c0 7.6-4.7 13.1-11 14.3-6.3-1.2-11-6.7-11-14.3V7l11-4.5Z"
        fill="none"
        stroke="rgb(var(--color-accent))"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <circle cx="16" cy="15" r="3.4" fill="rgb(var(--color-accent))" />
      <path
        d="M16 15v6.5"
        stroke="rgb(var(--color-accent))"
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  );
}

function navLinkClass({ isActive }: { isActive: boolean }): string {
  const base =
    "relative rounded-full px-3.5 py-1.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent";
  return isActive
    ? `${base} bg-accent text-accent-fg`
    : `${base} text-ink-muted hover:bg-surface-2 hover:text-ink`;
}

export default function App() {
  return (
    <div className="min-h-screen bg-bg text-ink">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-accent focus:px-4 focus:py-2 focus:text-accent-fg"
      >
        Saltar al contenido principal
      </a>

      <header className="sticky top-0 z-40 border-b border-border bg-bg/85 backdrop-blur supports-[backdrop-filter]:bg-bg/70">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2.5">
              <SentinelMark />
              <div className="leading-none">
                <p className="text-base font-bold tracking-tight text-ink">CENTINELA</p>
                <p className="text-[11px] font-medium uppercase tracking-wider text-ink-faint">
                  Blue Team Lab
                </p>
              </div>
            </div>

            <nav className="flex items-center gap-1 rounded-full border border-border bg-surface p-1">
              <NavLink to="/" end className={navLinkClass}>
                Panel SOC
              </NavLink>
              <NavLink to="/publico" className={navLinkClass}>
                Observatorio público
              </NavLink>
            </nav>
          </div>

          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1.5 text-xs font-medium text-ink-muted sm:flex">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-pulse-dot rounded-full bg-ok" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-ok" />
              </span>
              Motor activo
            </span>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <main id="main-content" className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
        <Routes>
          <Route path="/" element={<Soc />} />
          <Route path="/publico" element={<Observatorio />} />
        </Routes>
      </main>
    </div>
  );
}
