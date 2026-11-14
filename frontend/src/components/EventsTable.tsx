import React, { useState } from "react";
import type { CentinelaEvent, Severity } from "../lib/types";

const SEVERITY_CLASSES: Record<Severity, string> = {
  baja: "bg-slate-700 text-slate-200",
  media: "bg-amber-900 text-amber-200",
  alta: "bg-orange-900 text-orange-200",
  critica: "bg-red-900 text-red-200",
};

interface EventsTableProps {
  events: CentinelaEvent[];
}

export default function EventsTable({ events }: EventsTableProps) {
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const toggleExpand = (id: number) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800">
      <table className="min-w-full divide-y divide-slate-800 text-sm">
        <caption className="sr-only">Eventos de seguridad detectados por el motor de CENTINELA</caption>
        <thead className="bg-centinela-panel text-left text-slate-400">
          <tr>
            <th className="px-4 py-2">Hora</th>
            <th className="px-4 py-2">IP origen</th>
            <th className="px-4 py-2">Objetivo</th>
            <th className="px-4 py-2">Ruta</th>
            <th className="px-4 py-2">Veredicto</th>
            <th className="px-4 py-2">Categoría</th>
            <th className="px-4 py-2">Severidad</th>
            <th className="px-4 py-2">Técnica</th>
            <th className="px-4 py-2">Motor (µs)</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {events.map((event) => {
            const isExpanded = expandedId === event.id;
            return (
              <React.Fragment key={event.id}>
                <tr
                  onClick={() => toggleExpand(event.id)}
                  className="cursor-pointer hover:bg-slate-800/50 transition-colors"
                  title="Haz clic para inspeccionar detalles del triage IA"
                >
                  <td className="px-4 py-2 text-slate-400">
                    {new Date(event.ts).toLocaleTimeString("es-VE")}
                  </td>
                  <td className="px-4 py-2 font-mono">{event.src_ip}</td>
                  <td className="px-4 py-2">{event.target}</td>
                  <td className="px-4 py-2 font-mono text-xs">{event.path}</td>
                  <td className="px-4 py-2">
                    <span
                      className={
                        event.verdict === "block"
                          ? "rounded bg-red-900 px-2 py-0.5 text-red-200"
                          : "rounded bg-emerald-900 px-2 py-0.5 text-emerald-200"
                      }
                    >
                      {event.verdict === "block" ? "Bloqueado" : "Permitido"}
                    </span>
                  </td>
                  <td className="px-4 py-2">{event.category ?? "—"}</td>
                  <td className="px-4 py-2">
                    {event.severity ? (
                      <span className={`rounded px-2 py-0.5 ${SEVERITY_CLASSES[event.severity]}`}>
                        {event.severity}
                      </span>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="px-4 py-2">{event.technique_id ?? "—"}</td>
                  <td className="px-4 py-2">{event.engine_us}</td>
                </tr>
                {isExpanded && (
                  <tr className="bg-slate-900/90 border-t border-b border-centinela-accent/40">
                    <td colSpan={9} className="p-4 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-centinela-accent">
                            Incidente #{event.id}
                          </span>
                          <span className="text-xs text-slate-400">
                            Regla: <code className="font-mono text-amber-300">{event.rule_id ?? "N/A"}</code>
                          </span>
                          <span className="text-xs text-slate-400">
                            Técnica ATT&CK: <code className="font-mono text-cyan-300">{event.technique_id ?? "N/A"}</code>
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-xs">
                          <span className="text-slate-400">
                            Score ML:{" "}
                            <strong className="text-emerald-400 font-mono">
                              {event.ml_score !== null ? `${(event.ml_score * 100).toFixed(1)}%` : "Sin score"}
                            </strong>
                          </span>
                          <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
                            IA: {event.ai_status}
                          </span>
                        </div>
                      </div>

                      {/* Resumen del Copiloto IA */}
                      <div className="rounded border border-slate-800 bg-centinela-panel p-3">
                        <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 mb-1">
                          <span>🤖</span>
                          <span>Triage del Copiloto IA:</span>
                        </div>
                        <p className="text-sm text-slate-200">
                          {event.ai_summary ?? (
                            <span className="italic text-slate-500">
                              {event.verdict === "block"
                                ? "Procesamiento de triage de IA en curso..."
                                : "Tráfico legítimo — no requiere triage de IA."}
                            </span>
                          )}
                        </p>
                      </div>

                      {/* Muestra de Payload */}
                      {event.payload_sample && (
                        <div>
                          <span className="text-xs font-semibold text-slate-400 block mb-1">
                            Payload capturado (evidencia forense):
                          </span>
                          <pre className="overflow-x-auto rounded bg-slate-950 p-2 font-mono text-xs text-red-300 border border-red-950">
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
              <td colSpan={9} className="px-4 py-6 text-center text-slate-500">
                Sin eventos todavía. Lanza el simulador de tráfico para ver el panel en vivo.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
