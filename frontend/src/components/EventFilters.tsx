import { useId, useState } from "react";

import type { Severity } from "../lib/types";

export interface EventFiltersValue {
  severity: Severity | "";
  src_ip: string;
  since: string;
  until: string;
}

export const EMPTY_FILTERS: EventFiltersValue = {
  severity: "",
  src_ip: "",
  since: "",
  until: "",
};

const SEVERITIES: Severity[] = ["baja", "media", "alta", "critica"];

interface EventFiltersProps {
  value: EventFiltersValue;
  onApply: (value: EventFiltersValue) => void;
}

// Filtros del panel SOC: severidad, IP origen y rango de fechas, tal como
// exige el contrato de /api/events (docs/SPRINT-1.md sección 4). Los campos
// se editan en un borrador local y solo disparan la consulta al pulsar
// "Aplicar" o Enter, para no golpear la API en cada tecla.
export default function EventFilters({ value, onApply }: EventFiltersProps) {
  const [draft, setDraft] = useState<EventFiltersValue>(value);
  const severityId = useId();
  const ipId = useId();
  const sinceId = useId();
  const untilId = useId();

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    onApply(draft);
  };

  const handleClear = () => {
    setDraft(EMPTY_FILTERS);
    onApply(EMPTY_FILTERS);
  };

  const hasActiveFilters =
    value.severity !== "" || value.src_ip !== "" || value.since !== "" || value.until !== "";

  return (
    <form
      onSubmit={handleSubmit}
      className="flex flex-wrap items-end gap-4 rounded-lg border border-slate-800 bg-centinela-panel p-4"
      aria-label="Filtros de eventos"
    >
      <div className="flex flex-col gap-1">
        <label htmlFor={severityId} className="text-xs uppercase tracking-wide text-slate-400">
          Severidad
        </label>
        <select
          id={severityId}
          value={draft.severity}
          onChange={(event) =>
            setDraft((previous) => ({
              ...previous,
              severity: event.target.value as Severity | "",
            }))
          }
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-100 focus:border-centinela-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-centinela-accent"
        >
          <option value="">Todas</option>
          {SEVERITIES.map((severity) => (
            <option key={severity} value={severity}>
              {severity}
            </option>
          ))}
        </select>
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor={ipId} className="text-xs uppercase tracking-wide text-slate-400">
          IP origen
        </label>
        <input
          id={ipId}
          type="text"
          inputMode="numeric"
          placeholder="172.20.0.9"
          value={draft.src_ip}
          onChange={(event) =>
            setDraft((previous) => ({ ...previous, src_ip: event.target.value }))
          }
          className="w-40 rounded border border-slate-700 bg-slate-900 px-2 py-1.5 font-mono text-sm text-slate-100 focus:border-centinela-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-centinela-accent"
        />
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor={sinceId} className="text-xs uppercase tracking-wide text-slate-400">
          Desde
        </label>
        <input
          id={sinceId}
          type="datetime-local"
          value={draft.since}
          onChange={(event) =>
            setDraft((previous) => ({ ...previous, since: event.target.value }))
          }
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-100 focus:border-centinela-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-centinela-accent"
        />
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor={untilId} className="text-xs uppercase tracking-wide text-slate-400">
          Hasta
        </label>
        <input
          id={untilId}
          type="datetime-local"
          value={draft.until}
          onChange={(event) =>
            setDraft((previous) => ({ ...previous, until: event.target.value }))
          }
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-100 focus:border-centinela-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-centinela-accent"
        />
      </div>

      <div className="flex gap-2">
        <button
          type="submit"
          className="rounded bg-centinela-accent px-4 py-1.5 text-sm font-semibold text-slate-900 hover:opacity-90 focus-visible:ring-2 focus-visible:ring-centinela-accent focus-visible:ring-offset-2 focus-visible:ring-offset-centinela-panel"
        >
          Aplicar
        </button>
        {hasActiveFilters && (
          <button
            type="button"
            onClick={handleClear}
            className="rounded border border-slate-700 px-4 py-1.5 text-sm text-slate-300 hover:bg-slate-800 focus-visible:ring-2 focus-visible:ring-centinela-accent focus-visible:ring-offset-2 focus-visible:ring-offset-centinela-panel"
          >
            Limpiar
          </button>
        )}
      </div>
    </form>
  );
}
