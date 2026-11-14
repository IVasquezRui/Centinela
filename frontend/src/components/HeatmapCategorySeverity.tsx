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
  if (count === 0) return "bg-surface-2 text-ink-faint";
  const ratio = max > 0 ? count / max : 0;
  if (ratio > 0.66) return "bg-red-600 text-white dark:bg-red-500";
  if (ratio > 0.33) return "bg-orange-400 text-orange-950 dark:bg-orange-600 dark:text-orange-50";
  return "bg-amber-200 text-amber-900 dark:bg-amber-900/70 dark:text-amber-100";
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
    <div className="rounded-xl border border-border bg-surface p-4 shadow-card dark:shadow-card-dark">
      <table
        className="w-full text-center text-sm"
        role="table"
        aria-label="Mapa de calor categoría por severidad"
      >
        <thead>
          <tr>
            <th scope="col" className="px-2 py-1.5 text-left text-xs font-semibold uppercase tracking-wide text-ink-faint">
              Categoría
            </th>
            {SEVERITIES.map((severity) => (
              <th
                key={severity}
                scope="col"
                className="px-2 py-1.5 text-xs font-semibold uppercase tracking-wide text-ink-faint"
              >
                {severity}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {CATEGORIES.map((category) => (
            <tr key={category}>
              <th scope="row" className="px-2 py-1 text-left font-normal text-ink-muted">
                {CATEGORY_LABEL[category]}
              </th>
              {SEVERITIES.map((severity) => {
                const count = counts[category][severity];
                return (
                  <td key={severity} className="p-1">
                    <div
                      className={`flex h-10 items-center justify-center rounded-md font-mono text-sm transition-colors ${intensityClass(count, max)}`}
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
        <p className="mt-3 text-center text-sm text-ink-faint">
          Sin bloqueos todavía. El mapa se llena solo al lanzar el simulador de tráfico.
        </p>
      )}
    </div>
  );
}
