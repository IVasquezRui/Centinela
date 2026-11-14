import { useMemo } from "react";

import type { CentinelaEvent, Category, Severity } from "../lib/types";

const CATEGORIES: Category[] = ["sqli", "xss", "traversal", "cmdi", "scanner", "bruteforce"];
const SEVERITIES: Severity[] = ["baja", "media", "alta", "critica"];

const CATEGORY_LABEL: Record<Category, string> = {
  sqli: "SQLi",
  xss: "XSS",
  traversal: "Traversal",
  cmdi: "Cmd Injection",
  scanner: "Scanner",
  bruteforce: "Fuerza bruta",
};

interface HeatmapProps {
  events: CentinelaEvent[];
}

// Intensidad por umbral de conteo en vez de una escala continua: con el
// volumen de una demo de unas horas, una escala continua deja casi toda la
// grilla en el mismo tono. Los umbrales se recalibran fácil si el corpus
// de la demo cambia de tamaño.
function intensityClass(count: number, max: number): string {
  if (count === 0) return "bg-slate-900 text-slate-600";
  const ratio = max > 0 ? count / max : 0;
  if (ratio > 0.66) return "bg-red-700 text-white";
  if (ratio > 0.33) return "bg-orange-800 text-orange-100";
  return "bg-amber-950 text-amber-200";
}

// Mapa de calor categoría × severidad (fase F3 de docs/SPRINT-1.md). Se
// recalcula en memoria a partir de los eventos bloqueados ya cargados en
// Soc.tsx (fetch inicial + acumulación por SSE); no depende de un endpoint
// de agregación nuevo en el backend.
export default function HeatmapCategorySeverity({ events }: HeatmapProps) {
  const { counts, max } = useMemo(() => {
    const grid: Record<Category, Record<Severity, number>> = {
      sqli: { baja: 0, media: 0, alta: 0, critica: 0 },
      xss: { baja: 0, media: 0, alta: 0, critica: 0 },
      traversal: { baja: 0, media: 0, alta: 0, critica: 0 },
      cmdi: { baja: 0, media: 0, alta: 0, critica: 0 },
      scanner: { baja: 0, media: 0, alta: 0, critica: 0 },
      bruteforce: { baja: 0, media: 0, alta: 0, critica: 0 },
    };
    let maxCount = 0;

    for (const event of events) {
      if (!event.category || !event.severity) continue;
      grid[event.category][event.severity] += 1;
      maxCount = Math.max(maxCount, grid[event.category][event.severity]);
    }

    return { counts: grid, max: maxCount };
  }, [events]);

  const hasData = max > 0;

  return (
    <div className="rounded-lg border border-slate-800 bg-centinela-panel p-4">
      <table className="w-full text-center text-sm" role="table" aria-label="Mapa de calor categoría por severidad">
        <thead>
          <tr>
            <th scope="col" className="px-2 py-1 text-left text-xs uppercase tracking-wide text-slate-400">
              Categoría
            </th>
            {SEVERITIES.map((severity) => (
              <th
                key={severity}
                scope="col"
                className="px-2 py-1 text-xs uppercase tracking-wide text-slate-400"
              >
                {severity}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {CATEGORIES.map((category) => (
            <tr key={category}>
              <th scope="row" className="px-2 py-1 text-left font-normal text-slate-300">
                {CATEGORY_LABEL[category]}
              </th>
              {SEVERITIES.map((severity) => {
                const count = counts[category][severity];
                return (
                  <td key={severity} className="p-1">
                    <div
                      className={`flex h-10 items-center justify-center rounded font-mono text-sm ${intensityClass(count, max)}`}
                      title={`${CATEGORY_LABEL[category]} · ${severity}: ${count}`}
                    >
                      {count}
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      {!hasData && (
        <p className="mt-3 text-center text-sm text-slate-500">
          Sin bloqueos todavía. El mapa se llena solo al lanzar el simulador de tráfico.
        </p>
      )}
    </div>
  );
}
