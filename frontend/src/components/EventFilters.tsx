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

const fieldClass =
  "rounded-lg border border-border bg-surface-2 px-2.5 py-1.5 text-sm text-ink placeholder:text-ink-faint focus:outline-none focus-visible:ring-2 focus-visible:ring-accent";

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
      className="flex flex-wrap items-end gap-4 rounded-xl border border-border bg-surface p-4 shadow-card dark:shadow-card-dark"
      aria-label="Filtros de eventos"
    >
      <div className="flex flex-col gap-1">
        <label htmlFor={severityId} className="text-xs font-medium uppercase tracking-wide text-ink-faint">
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
          className={fieldClass}
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
        <label htmlFor={ipId} className="text-xs font-medium uppercase tracking-wide text-ink-faint">
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
          className={`w-40 font-mono ${fieldClass}`}
        />
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor={sinceId} className="text-xs font-medium uppercase tracking-wide text-ink-faint">
          Desde
        </label>
        <input
          id={sinceId}
          type="datetime-local"
          value={draft.since}
          onChange={(event) =>
            setDraft((previous) => ({ ...previous, since: event.target.value }))
          }
          className={fieldClass}
        />
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor={untilId} className="text-xs font-medium uppercase tracking-wide text-ink-faint">
          Hasta
        </label>
        <input
          id={untilId}
          type="datetime-local"
          value={draft.until}
          onChange={(event) =>
            setDraft((previous) => ({ ...previous, until: event.target.value }))
          }
          className={fieldClass}
        />
      </div>

      <div className="flex gap-2">
        <button
          type="submit"
          className="rounded-lg bg-accent px-4 py-1.5 text-sm font-semibold text-accent-fg transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
        >
          Aplicar
        </button>
        {hasActiveFilters && (
          <button
            type="button"
            onClick={handleClear}
            className="rounded-lg border border-border px-4 py-1.5 text-sm text-ink-muted transition-colors hover:bg-surface-2 hover:text-ink focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
          >
            Limpiar
          </button>
        )}
      </div>
    </form>
  );
}
