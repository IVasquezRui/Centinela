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
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800">
      <table className="min-w-full divide-y divide-slate-800 text-sm">
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
          {events.map((event) => (
            <tr key={event.id} className="hover:bg-slate-800/50">
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
          ))}
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
