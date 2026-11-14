import { useCallback, useEffect, useRef, useState } from "react";

import { api, subscribeToStream } from "../lib/api";
import type { AuditVerification, CentinelaEvent, QuarantinedIp, Stats } from "../lib/types";
import EventFilters, { EMPTY_FILTERS, type EventFiltersValue } from "../components/EventFilters";
import EventsTable from "../components/EventsTable";
import HeatmapCategorySeverity from "../components/HeatmapCategorySeverity";
import KpiCard from "../components/KpiCard";

const TABLE_LIMIT = 100;
// /api/events limita `limit` a 1000 (ver centinela-core/app/api/soc.py);
// el fetch inicial del mapa de calor no puede pedir más que eso.
const HEATMAP_FETCH_LIMIT = 1000;
// Tope del histórico que acumula el mapa de calor contando también lo que
// va llegando por SSE: no hay límite del lado del servidor para esto (es
// solo un slice en memoria del navegador), así que puede crecer más que
// el fetch inicial sin volver a pedirle nada a la API.
const HEATMAP_HISTORY_LIMIT = 5000;

function toApiParams(filters: EventFiltersValue): Record<string, string> {
  const params: Record<string, string> = { limit: String(TABLE_LIMIT) };
  if (filters.severity) params.severity = filters.severity;
  if (filters.src_ip) params.src_ip = filters.src_ip;
  if (filters.since) params.since = filters.since;
  if (filters.until) params.until = filters.until;
  return params;
}

function matchesFilters(event: CentinelaEvent, filters: EventFiltersValue): boolean {
  if (filters.severity && event.severity !== filters.severity) return false;
  if (filters.src_ip && event.src_ip !== filters.src_ip) return false;
  // Comparación por instante real (Date), no por string: event.ts llega con
  // offset de zona horaria del servidor y los inputs datetime-local son hora
  // local del navegador sin offset; compararlos como texto da falsos
  // negativos/positivos cerca del límite.
  const eventTime = new Date(event.ts).getTime();
  if (filters.since && eventTime < new Date(filters.since).getTime()) return false;
  if (filters.until && eventTime > new Date(filters.until).getTime()) return false;
  return true;
}

// Panel SOC — fase F2/F3 de docs/SPRINT-1.md:
// 4 tarjetas KPI, tabla de eventos filtrable, mapa de calor categoría x
// severidad, conexión SSE en vivo, panel de IPs en cuarentena y
// verificación de la cadena de auditoría.
export default function Soc() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [events, setEvents] = useState<CentinelaEvent[]>([]);
  const [heatmapEvents, setHeatmapEvents] = useState<CentinelaEvent[]>([]);
  const [blocklist, setBlocklist] = useState<QuarantinedIp[]>([]);
  const [audit, setAudit] = useState<AuditVerification | null>(null);
  const [filters, setFilters] = useState<EventFiltersValue>(EMPTY_FILTERS);
  const filtersRef = useRef(filters);
  filtersRef.current = filters;

  const loadEvents = useCallback(async (nextFilters: EventFiltersValue) => {
    try {
      const eventsResponse = await api.events(toApiParams(nextFilters));
      setEvents(eventsResponse);
    } catch {
      // API todavía no disponible; se deja la tabla como estaba.
    }
  }, []);

  const handleApplyFilters = (nextFilters: EventFiltersValue) => {
    setFilters(nextFilters);
    loadEvents(nextFilters);
  };

  useEffect(() => {
    const load = async () => {
      try {
        const [statsResponse, eventsResponse, blocklistResponse, heatmapResponse] =
          await Promise.all([
            api.stats(),
            api.events(toApiParams(EMPTY_FILTERS)),
            api.blocklist(),
            api.events({ limit: String(HEATMAP_FETCH_LIMIT) }),
          ]);
        setStats(statsResponse);
        setEvents(eventsResponse);
        setBlocklist(blocklistResponse);
        setHeatmapEvents(heatmapResponse);
      } catch {
        // API todavía no disponible (ej. durante F0 antes de levantar el
        // entorno); el panel se queda en su estado vacío sin romper.
      }
    };
    load();

    const unsubscribe = subscribeToStream((event) => {
      // La tabla respeta los filtros activos; el mapa de calor acumula todo
      // lo bloqueado, filtros aparte, para reflejar el panorama completo.
      if (matchesFilters(event, filtersRef.current)) {
        setEvents((previous) => [event, ...previous].slice(0, TABLE_LIMIT));
      }
      if (event.verdict === "block") {
        setHeatmapEvents((previous) => [event, ...previous].slice(0, HEATMAP_HISTORY_LIMIT));
      }
    });

    return unsubscribe;
  }, []);

  const handleVerifyAudit = async () => {
    const result = await api.auditVerify();
    setAudit(result);
  };

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold lg:text-4xl">Panel SOC</h1>

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
        <EventFilters value={filters} onApply={handleApplyFilters} />
        <p className="my-2 text-xs text-slate-500" role="status">
          {events.length} resultado{events.length === 1 ? "" : "s"}
          {filters.severity || filters.src_ip || filters.since || filters.until
            ? " (filtrado)"
            : ""}
        </p>
        <EventsTable events={events} />
      </section>

      <section>
        <h2 className="mb-2 text-lg font-semibold">Mapa de calor — categoría × severidad</h2>
        <HeatmapCategorySeverity events={heatmapEvents} />
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
              className="rounded bg-centinela-accent px-4 py-2 font-semibold text-slate-900 hover:opacity-90 focus-visible:ring-2 focus-visible:ring-centinela-accent focus-visible:ring-offset-2 focus-visible:ring-offset-centinela-panel"
            >
              Verificar auditoría
            </button>
            {audit && (
              <p
                role="status"
                className={`mt-3 ${audit.valid ? "text-centinela-ok" : "text-centinela-danger"}`}
              >
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
