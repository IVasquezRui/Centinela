import { useEffect, useState } from "react";

import { api, subscribeToStream } from "../lib/api";
import type { AuditVerification, CentinelaEvent, QuarantinedIp, Stats } from "../lib/types";
import EventsTable from "../components/EventsTable";
import KpiCard from "../components/KpiCard";

// Panel SOC — fase F2/F3 de docs/SPRINT-1.md:
// 4 tarjetas KPI, tabla de eventos filtrable, conexión SSE en vivo,
// panel de IPs en cuarentena y verificación de la cadena de auditoría.
export default function Soc() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [events, setEvents] = useState<CentinelaEvent[]>([]);
  const [blocklist, setBlocklist] = useState<QuarantinedIp[]>([]);
  const [audit, setAudit] = useState<AuditVerification | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [statsResponse, eventsResponse, blocklistResponse] = await Promise.all([
          api.stats(),
          api.events({ limit: "50" }),
          api.blocklist(),
        ]);
        setStats(statsResponse);
        setEvents(eventsResponse);
        setBlocklist(blocklistResponse);
      } catch {
        // API todavía no disponible (ej. durante F0 antes de levantar el
        // entorno); el panel se queda en su estado vacío sin romper.
      }
    };
    load();

    const unsubscribe = subscribeToStream((event) => {
      setEvents((previous) => [event, ...previous].slice(0, 50));
    });

    return unsubscribe;
  }, []);

  const handleVerifyAudit = async () => {
    const result = await api.auditVerify();
    setAudit(result);
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Panel SOC</h1>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard label="Peticiones totales" value={stats?.total_requests ?? "—"} />
        <KpiCard label="Bloqueos" value={stats?.blocked_requests ?? "—"} tone="danger" />
        <KpiCard label="IPs en cuarentena" value={stats?.quarantined_ips ?? "—"} tone="warning" />
        <KpiCard
          label="Latencia del motor (p95, µs)"
          value={stats?.engine_latency_p95_us?.toFixed(0) ?? "—"}
          tone="ok"
        />
      </div>

      <section>
        <h2 className="mb-2 text-lg font-semibold">Eventos en vivo</h2>
        <EventsTable events={events} />
      </section>

      <section className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div>
          <h2 className="mb-2 text-lg font-semibold">IPs en cuarentena</h2>
          <ul className="space-y-1 rounded-lg border border-slate-800 bg-centinela-panel p-4 text-sm">
            {blocklist.length === 0 && (
              <li className="text-slate-500">Ninguna IP en cuarentena actualmente.</li>
            )}
            {blocklist.map((entry) => (
              <li key={entry.ip} className="font-mono">
                {entry.ip} — {entry.quarantined_for_seconds}s restantes
              </li>
            ))}
          </ul>
        </div>

        <div>
          <h2 className="mb-2 text-lg font-semibold">Auditoría (cadena de hashes)</h2>
          <div className="rounded-lg border border-slate-800 bg-centinela-panel p-4 text-sm">
            <button
              onClick={handleVerifyAudit}
              className="rounded bg-centinela-accent px-4 py-2 font-semibold text-slate-900 hover:opacity-90"
            >
              Verificar auditoría
            </button>
            {audit && (
              <p className={`mt-3 ${audit.valid ? "text-centinela-ok" : "text-centinela-danger"}`}>
                {audit.valid
                  ? `Cadena íntegra (${audit.entries_checked} entradas verificadas).`
                  : `Cadena rota en el registro #${audit.broken_at_id}.`}
              </p>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
