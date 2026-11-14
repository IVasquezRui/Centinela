import React, { useState } from "react";

import type { CentinelaEvent, Severity } from "../lib/types";

const SEVERITY_CLASSES: Record<Severity, string> = {
  baja: "bg-slate-200 text-slate-700 dark:bg-slate-700/60 dark:text-slate-200",
  media: "bg-amber-200 text-amber-900 dark:bg-amber-900/60 dark:text-amber-200",
  alta: "bg-orange-200 text-orange-900 dark:bg-orange-900/60 dark:text-orange-200",
  critica: "bg-red-200 text-red-900 dark:bg-red-900/60 dark:text-red-200",
};

function CopilotIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" className="h-3.5 w-3.5" aria-hidden="true">
      <rect x="4" y="7" width="16" height="12" rx="3" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="9" cy="13" r="1.3" fill="currentColor" />
      <circle cx="15" cy="13" r="1.3" fill="currentColor" />
      <path d="M12 7V4m-3 0h6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 20 20"
      fill="none"
      className={`h-4 w-4 shrink-0 text-ink-faint transition-transform duration-200 ${open ? "rotate-90" : ""}`}
      aria-hidden="true"
    >
      <path d="M7 5l6 5-6 5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

interface EventsTableProps {
  events: CentinelaEvent[];
}

export default function EventsTable({ events }: EventsTableProps) {
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const toggleExpand = (id: number) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="overflow-x-auto rounded-xl border border-border bg-surface shadow-card dark:shadow-card-dark">
      <table className="min-w-full divide-y divide-border text-sm">
        <caption className="sr-only">Eventos de seguridad detectados por el motor de CENTINELA</caption>
        <thead className="bg-surface-2 text-left text-ink-faint">
          <tr>
            <th className="w-8 px-2 py-2" aria-hidden="true" />
            <th className="px-4 py-2 text-xs font-semibold uppercase tracking-wide">Hora</th>
            <th className="px-4 py-2 text-xs font-semibold uppercase tracking-wide">IP origen</th>
            <th className="px-4 py-2 text-xs font-semibold uppercase tracking-wide">Objetivo</th>
            <th className="px-4 py-2 text-xs font-semibold uppercase tracking-wide">Ruta</th>
            <th className="px-4 py-2 text-xs font-semibold uppercase tracking-wide">Veredicto</th>
            <th className="px-4 py-2 text-xs font-semibold uppercase tracking-wide">Categoría</th>
            <th className="px-4 py-2 text-xs font-semibold uppercase tracking-wide">Severidad</th>
            <th className="px-4 py-2 text-xs font-semibold uppercase tracking-wide">Técnica</th>
            <th className="px-4 py-2 text-xs font-semibold uppercase tracking-wide">Motor (µs)</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {events.map((event) => {
            const isExpanded = expandedId === event.id;
            return (
              <React.Fragment key={event.id}>
                <tr
                  onClick={() => toggleExpand(event.id)}
                  className="cursor-pointer transition-colors hover:bg-surface-hover"
                  title="Haz clic para inspeccionar el detalle del evento"
                  aria-expanded={isExpanded}
                >
                  <td className="px-2 py-2 text-center">
                    <ChevronIcon open={isExpanded} />
                  </td>
                  <td className="px-4 py-2 text-ink-muted">
                    {new Date(event.ts).toLocaleTimeString("es-VE")}
                  </td>
                  <td className="px-4 py-2 font-mono text-ink">{event.src_ip}</td>
                  <td className="px-4 py-2 text-ink">{event.target}</td>
                  <td className="px-4 py-2 font-mono text-xs text-ink-muted">{event.path}</td>
                  <td className="px-4 py-2">
                    <span
                      className={
                        event.verdict === "block"
                          ? "rounded-full bg-red-200 px-2 py-0.5 text-xs font-medium text-red-900 dark:bg-red-900/60 dark:text-red-200"
                          : "rounded-full bg-emerald-200 px-2 py-0.5 text-xs font-medium text-emerald-900 dark:bg-emerald-900/60 dark:text-emerald-200"
                      }
                    >
                      {event.verdict === "block" ? "Bloqueado" : "Permitido"}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-ink-muted">{event.category ?? "—"}</td>
                  <td className="px-4 py-2">
                    {event.severity ? (
                      <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${SEVERITY_CLASSES[event.severity]}`}>
                        {event.severity}
                      </span>
                    ) : (
                      <span className="text-ink-faint">—</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-ink-muted">{event.technique_id ?? "—"}</td>
                  <td className="px-4 py-2 text-ink-muted">{event.engine_us}</td>
                </tr>
                {isExpanded && (
                  <tr className="bg-surface-2/60">
                    <td colSpan={10} className="space-y-3 p-4">
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-2">
                        <div className="flex flex-wrap items-center gap-3">
                          <span className="font-semibold text-accent">Incidente #{event.id}</span>
                          <span className="text-xs text-ink-muted">
                            Regla:{" "}
                            <code className="rounded bg-surface-2 px-1 py-0.5 font-mono text-amber-700 dark:text-amber-300">
                              {event.rule_id ?? "N/A"}
                            </code>
                          </span>
                          <span className="text-xs text-ink-muted">
                            Técnica ATT&CK:{" "}
                            <code className="rounded bg-surface-2 px-1 py-0.5 font-mono text-sky-700 dark:text-cyan-300">
                              {event.technique_id ?? "N/A"}
                            </code>
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-xs">
                          <span className="text-ink-muted">
                            Score ML:{" "}
                            <strong className="font-mono text-emerald-700 dark:text-emerald-400">
                              {event.ml_score !== null ? `${(event.ml_score * 100).toFixed(1)}%` : "Sin score"}
                            </strong>
                          </span>
                          <span className="rounded-full bg-surface-2 px-2 py-0.5 text-ink-muted">
                            IA: {event.ai_status}
                          </span>
                        </div>
                      </div>

                      <div className="rounded-lg border border-border bg-surface p-3">
                        <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-ink-muted">
                          <CopilotIcon />
                          <span>Triage del copiloto IA</span>
                        </div>
                        <p className="text-sm text-ink">
                          {event.ai_summary ?? (
                            <span className="italic text-ink-faint">
                              {event.verdict === "block"
                                ? "Procesamiento de triage de IA en curso..."
                                : "Tráfico legítimo — no requiere triage de IA."}
                            </span>
                          )}
                        </p>
                      </div>

                      {event.payload_sample && (
                        <div>
                          <span className="mb-1 block text-xs font-semibold text-ink-faint">
                            Payload capturado (evidencia forense):
                          </span>
                          <pre className="overflow-x-auto rounded-lg border border-red-900/30 bg-red-950/90 p-2 font-mono text-xs text-red-200 dark:border-red-950 dark:bg-slate-950">
                            {event.payload_sample}
                          </pre>
                        </div>
                      )}
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
          {events.length === 0 && (
            <tr>
              <td colSpan={10} className="px-4 py-6 text-center text-ink-faint">
                Sin eventos todavía. Lanza el simulador de tráfico para ver el panel en vivo.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
