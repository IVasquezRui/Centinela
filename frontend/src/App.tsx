import { Link, Route, Routes } from "react-router-dom";

import Observatorio from "./pages/Observatorio";
import Soc from "./pages/Soc";

export default function App() {
  return (
    <div className="min-h-screen bg-centinela-bg">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-centinela-accent focus:px-4 focus:py-2 focus:text-slate-900"
      >
        Saltar al contenido principal
      </a>
      <nav className="flex items-center gap-6 border-b border-slate-800 px-6 py-4">
        <span className="text-lg font-bold tracking-wide text-centinela-accent">
          CENTINELA
        </span>
        <Link
          to="/"
          className="rounded text-sm text-slate-300 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-centinela-accent"
        >
          Panel SOC
        </Link>
        <Link
          to="/publico"
          className="rounded text-sm text-slate-300 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-centinela-accent"
        >
          Observatorio público
        </Link>
      </nav>

      <main id="main-content" className="p-6">
        <Routes>
          <Route path="/" element={<Soc />} />
          <Route path="/publico" element={<Observatorio />} />
        </Routes>
      </main>
    </div>
  );
}
