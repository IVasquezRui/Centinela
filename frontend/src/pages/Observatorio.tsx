import { useEffect, useState } from "react";

import { api } from "../lib/api";
import type { AlertaPublica, Indicadores } from "../lib/types";
import KpiCard from "../components/KpiCard";

const TENDENCIA_LABEL: Record<Indicadores["tendencia"], string> = {
  al_alza: "Al alza ⬆",
  a_la_baja: "A la baja ⬇",
  estable: "Estable →",
};

// Vista pública del Observatorio (SDD #40) — sin autenticación, lenguaje
// claro, sin datos personales ni identificadores de víctimas. Se alimenta
// automáticamente del mismo motor que protege a los entes (fase F4).
export default function Observatorio() {
  const [indicadores, setIndicadores] = useState<Indicadores | null>(null);
  const [alertas, setAlertas] = useState<AlertaPublica[]>([]);

  useEffect(() => {
    const load = async () => {
      try {
        const [indicadoresResponse, alertasResponse] = await Promise.all([
          api.publicIndicadores(),
          api.publicAlertas(),
        ]);
        setIndicadores(indicadoresResponse);
        setAlertas(alertasResponse);
      } catch {
        // El Observatorio es de solo lectura: si la API no responde, se
        // muestra el estado vacío sin romper la vista ciudadana.
      }
    };
    load();
  }, []);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-3xl font-bold lg:text-4xl">Observatorio Nacional de Ciberseguridad</h1>
        <p className="mt-1 max-w-2xl text-slate-400">
          Panorama de amenazas agregado y anonimizado. No se publica
          información que identifique a personas, empresas o entes
          concretos.
        </p>
      </header>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <KpiCard
          label="Incidentes (30 días)"
          value={indicadores?.incidentes_ultimos_30_dias ?? "—"}
        />
        <KpiCard
          label="Amenaza predominante"
          value={indicadores?.tipo_amenaza_predominante ?? "—"}
        />
        <KpiCard label="Sector más afectado" value={indicadores?.sector_mas_afectado ?? "—"} />
        <KpiCard label="Severidad promedio" value={indicadores?.severidad_promedio ?? "—"} />
        <KpiCard
          label="Tendencia"
          value={indicadores ? TENDENCIA_LABEL[indicadores.tendencia] : "—"}
        />
      </div>

      <section>
        <h2 className="mb-2 text-lg font-semibold">Alertas activas</h2>
        <div className="space-y-3">
          {alertas.length === 0 && (
            <p className="text-slate-500">No hay alertas activas por el momento.</p>
          )}
          {alertas.map((alerta, index) => (
            <article
              key={index}
              className="rounded-lg border border-slate-800 bg-centinela-panel p-4"
            >
              <div className="flex items-center justify-between">
                <p className="font-semibold">{alerta.descripcion}</p>
                <span className="text-xs text-slate-400">{alerta.fecha}</span>
              </div>
              <p className="mt-2 text-sm text-slate-300">{alerta.recomendacion}</p>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
