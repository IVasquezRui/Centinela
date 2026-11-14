import { Link, Route, Routes } from "react-router-dom";

import Observatorio from "./pages/Observatorio";
import Soc from "./pages/Soc";

export default function App() {
  return (
    <div className="min-h-screen bg-centinela-bg">
      <nav className="flex items-center gap-6 border-b border-slate-800 px-6 py-4">
        <span className="text-lg font-bold tracking-wide text-centinela-accent">
          CENTINELA
        </span>
        <Link to="/" className="text-sm text-slate-300 hover:text-white">
          Panel SOC
        </Link>
        <Link to="/publico" className="text-sm text-slate-300 hover:text-white">
          Observatorio público
        </Link>
      </nav>

      <main className="p-6">
        <Routes>
          <Route path="/" element={<Soc />} />
          <Route path="/publico" element={<Observatorio />} />
        </Routes>
      </main>
    </div>
  );
}
