import { useEffect, useMemo, useState } from "react";

import { api } from "../lib/api";
import type { AlertaPublica, Indicadores, Severity } from "../lib/types";

const SEVERITY_LABEL: Record<Severity, string> = {
  baja: "Baja",
  media: "Media",
  alta: "Alta",
  critica: "Crítica",
};

const SEVERITY_BADGE: Record<Severity, string> = {
  baja: "bg-slate-200 text-slate-700 dark:bg-slate-700/60 dark:text-slate-200",
  media: "bg-amber-200 text-amber-900 dark:bg-amber-900/60 dark:text-amber-200",
  alta: "bg-orange-200 text-orange-900 dark:bg-orange-900/60 dark:text-orange-200",
  critica: "bg-red-200 text-red-900 dark:bg-red-900/60 dark:text-red-200",
};

function TrendArrow({ tendencia }: { tendencia: Indicadores["tendencia"] }) {
  if (tendencia === "al_alza") {
    return (
      <svg viewBox="0 0 24 24" fill="none" className="h-6 w-6 text-danger" aria-hidden="true">
        <path d="M4 16 10 10l4 4 6-7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M15 7h5v5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  if (tendencia === "a_la_baja") {
    return (
      <svg viewBox="0 0 24 24" fill="none" className="h-6 w-6 text-ok" aria-hidden="true">
        <path d="M4 8 10 14l4-4 6 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M15 17h5v-5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 24 24" fill="none" className="h-6 w-6 text-ink-faint" aria-hidden="true">
      <path d="M4 12h16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <path d="M15 7l5 5-5 5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const TENDENCIA_LABEL: Record<Indicadores["tendencia"], string> = {
  al_alza: "Al alza",
  a_la_baja: "A la baja",
  estable: "Estable",
};

const TENDENCIA_TONE: Record<Indicadores["tendencia"], string> = {
  al_alza: "text-danger",
  a_la_baja: "text-ok",
  estable: "text-ink-faint",
};

function AlertIcon({ severity }: { severity: Severity | null }) {
  const tone =
    severity === "critica" || severity === "alta"
      ? "text-danger"
      : severity === "media"
        ? "text-warning"
        : "text-ink-faint";
  return (
    <svg viewBox="0 0 24 24" fill="none" className={`h-5 w-5 shrink-0 ${tone}`} aria-hidden="true">
      <path
        d="M12 3 2.5 20h19L12 3Z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path d="M12 9.5v4.2" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      <circle cx="12" cy="16.7" r="1" fill="currentColor" />
    </svg>
  );
}

// Distribución por tipo de amenaza entre las alertas visibles: no hay un
// endpoint de agregación por categoría en /api/public, así que se agrupa en
// el cliente por la descripción en lenguaje claro que ya manda el backend
// (1:1 con la categoría real, ver api/public.py::_CATEGORY_LABEL_CLARO).
// Son datos reales de las alertas ya cargadas, no una muestra inventada.
function useDistribucion(alertas: AlertaPublica[]) {
  return useMemo(() => {
    const counts = new Map<string, number>();
    for (const alerta of alertas) {
      counts.set(alerta.descripcion, (counts.get(alerta.descripcion) ?? 0) + 1);
    }
    const max = Math.max(1, ...counts.values());
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([descripcion, count]) => ({ descripcion, count, ratio: count / max }));
  }, [alertas]);
}

// Vista pública del Observatorio (SDD #40) — sin autenticación, lenguaje
// claro, sin datos personales ni identificadores de víctimas. Se alimenta
// automáticamente del mismo motor que protege a los entes (fase F4).
export default function Observatorio() {
  const [indicadores, setIndicadores] = useState<Indicadores | null>(null);
  const [alertas, setAlertas] = useState<AlertaPublica[]>([]);
  const [loadedAt, setLoadedAt] = useState<Date | null>(null);
  const distribucion = useDistribucion(alertas);

  useEffect(() => {
    const load = async () => {
      try {
        const [indicadoresResponse, alertasResponse] = await Promise.all([
          api.publicIndicadores(),
          api.publicAlertas(),
        ]);
        setIndicadores(indicadoresResponse);
        setAlertas(alertasResponse);
        setLoadedAt(new Date());
      } catch {
        // El Observatorio es de solo lectura: si la API no responde, se
        // muestra el estado vacío sin romper la vista ciudadana.
      }
    };
    load();
  }, []);

  return (
    <div className="space-y-8">
      <header className="overflow-hidden rounded-2xl border border-border bg-gradient-to-br from-surface to-surface-2 p-6 shadow-card dark:shadow-card-dark sm:p-8">
        <p className="text-xs font-semibold uppercase tracking-wider text-accent">
          Gobernanza del riesgo ciber · Vista pública
        </p>
        <h1 className="mt-2 max-w-2xl text-3xl font-bold tracking-tight text-ink lg:text-4xl">
          Observatorio Nacional de Ciberseguridad
        </h1>
        <p className="mt-3 max-w-2xl text-ink-muted">
          Panorama de amenazas agregado y anonimizado, alimentado en vivo por los entes que
          CENTINELA protege. No se publica información que identifique a personas, empresas o
          entes concretos.
        </p>
        {loadedAt && (
          <p className="mt-4 text-xs text-ink-faint">
            Actualizado {loadedAt.toLocaleDateString("es-VE", { day: "2-digit", month: "long" })} ·{" "}
            {loadedAt.toLocaleTimeString("es-VE")}
          </p>
        )}
      </header>

      <section className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-2xl border border-border bg-surface p-6 shadow-card dark:shadow-card-dark lg:col-span-1">
          <p className="text-xs font-semibold uppercase tracking-wide text-ink-faint">
            Incidentes · últimos 30 días
          </p>
          <p className="mt-3 text-5xl font-bold text-ink">
            {indicadores?.incidentes_ultimos_30_dias ?? "—"}
          </p>
          {indicadores && (
            <div className={`mt-3 flex items-center gap-1.5 text-sm font-medium ${TENDENCIA_TONE[indicadores.tendencia]}`}>
              <TrendArrow tendencia={indicadores.tendencia} />
              {TENDENCIA_LABEL[indicadores.tendencia]} respecto al período anterior
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 lg:col-span-2">
          <div className="rounded-2xl border border-border bg-surface p-5 shadow-card dark:shadow-card-dark">
            <p className="text-xs font-semibold uppercase tracking-wide text-ink-faint">
              Amenaza predominante
            </p>
            <p className="mt-2 text-lg font-bold leading-snug text-ink">
              {indicadores?.tipo_amenaza_predominante ?? "—"}
            </p>
          </div>
          <div className="rounded-2xl border border-border bg-surface p-5 shadow-card dark:shadow-card-dark">
            <p className="text-xs font-semibold uppercase tracking-wide text-ink-faint">
              Sector más afectado
            </p>
            <p className="mt-2 text-lg font-bold leading-snug text-ink">
              {indicadores?.sector_mas_afectado ?? "—"}
            </p>
          </div>
          <div className="rounded-2xl border border-border bg-surface p-5 shadow-card dark:shadow-card-dark">
            <p className="text-xs font-semibold uppercase tracking-wide text-ink-faint">
              Severidad promedio
            </p>
            <p className="mt-2">
              {indicadores?.severidad_promedio ? (
                <span
                  className={`inline-block rounded-full px-2.5 py-1 text-base font-bold ${SEVERITY_BADGE[indicadores.severidad_promedio]}`}
                >
                  {SEVERITY_LABEL[indicadores.severidad_promedio]}
                </span>
              ) : (
                <span className="text-lg font-bold text-ink">—</span>
              )}
            </p>
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <div className="rounded-2xl border border-border bg-surface p-6 shadow-card dark:shadow-card-dark lg:col-span-2">
          <h2 className="text-base font-semibold text-ink">Tipos de amenaza registrados</h2>
          <p className="mt-0.5 text-xs text-ink-faint">Distribución entre las alertas activas</p>
          <div className="mt-5 space-y-3">
            {distribucion.length === 0 && (
              <p className="text-sm text-ink-faint">Sin datos suficientes todavía.</p>
            )}
            {distribucion.map((item) => (
              <div key={item.descripcion}>
                <div className="flex items-baseline justify-between gap-2 text-sm">
                  <span className="text-ink-muted">{item.descripcion}</span>
                  <span className="shrink-0 font-mono font-semibold text-ink">{item.count}</span>
                </div>
                <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-2">
                  <div
                    className="h-full rounded-full bg-accent transition-all duration-500"
                    style={{ width: `${Math.max(6, item.ratio * 100)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="lg:col-span-3">
          <h2 className="text-base font-semibold text-ink">Alertas activas</h2>
          <p className="mt-0.5 text-xs text-ink-faint">
            En lenguaje claro, sin tecnicismos ni datos que identifiquen a nadie
          </p>
          <div className="mt-4 space-y-3">
            {alertas.length === 0 && (
              <p className="rounded-2xl border border-dashed border-border p-6 text-center text-sm text-ink-faint">
                No hay alertas activas por el momento.
              </p>
            )}
            {alertas.map((alerta, index) => (
              <article
                key={index}
                className="flex gap-3 rounded-2xl border border-border bg-surface p-4 shadow-card transition-shadow hover:shadow-glow dark:shadow-card-dark"
              >
                <AlertIcon severity={alerta.severidad} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                    <p className="font-semibold text-ink">{alerta.descripcion}</p>
                    <span className="shrink-0 text-xs text-ink-faint">{alerta.fecha}</span>
                  </div>
                  <p className="mt-1.5 text-sm text-ink-muted">{alerta.recomendacion}</p>
                </div>
              </article>
            ))}
          </div>
        </div>
      </section>

      <footer className="rounded-xl border border-dashed border-border p-4 text-xs text-ink-faint">
        Los indicadores se calculan automáticamente a partir de los eventos bloqueados por el
        motor de CENTINELA en cada ente. Ningún dato aquí identifica a una persona, empresa o
        ente concreto — ver{" "}
        <span className="font-medium text-ink-muted">docs/SDD.md</span> para el detalle de qué se
        agrega y cómo.
      </footer>
    </div>
  );
}
