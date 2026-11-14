interface KpiCardProps {
  label: string;
  value: string | number;
  tone?: "default" | "danger" | "warning" | "ok";
  hint?: string;
}

const TONE_CLASSES: Record<NonNullable<KpiCardProps["tone"]>, string> = {
  default: "text-ink",
  danger: "text-danger",
  warning: "text-warning",
  ok: "text-ok",
};

const TONE_DOT: Record<NonNullable<KpiCardProps["tone"]>, string> = {
  default: "bg-ink-faint",
  danger: "bg-danger",
  warning: "bg-warning",
  ok: "bg-ok",
};

// Las tarjetas numéricas (latencia, conteos) se leen desde el fondo de una
// sala con una tipografía grande; los indicadores de texto largo del
// Observatorio ("tipo de amenaza predominante", frases completas en
// lenguaje claro) se desbordarían con el mismo tamaño, así que el valor se
// escala según cuán corto sea.
function valueSizeClass(value: string | number): string {
  const text = String(value);
  if (text.length <= 6) return "text-4xl lg:text-5xl";
  if (text.length <= 16) return "text-2xl lg:text-3xl";
  return "text-lg lg:text-xl";
}

export default function KpiCard({ label, value, tone = "default", hint }: KpiCardProps) {
  return (
    <div className="rounded-xl border border-border bg-surface p-5 shadow-card dark:shadow-card-dark">
      <div className="flex items-center gap-1.5">
        <span className={`h-1.5 w-1.5 rounded-full ${TONE_DOT[tone]}`} aria-hidden="true" />
        <p className="text-xs font-semibold uppercase tracking-wide text-ink-faint">{label}</p>
      </div>
      <p
        className={`mt-2.5 font-bold leading-tight ${valueSizeClass(value)} ${TONE_CLASSES[tone]}`}
      >
        {value}
      </p>
      {hint && <p className="mt-1 text-xs text-ink-faint">{hint}</p>}
    </div>
  );
}
