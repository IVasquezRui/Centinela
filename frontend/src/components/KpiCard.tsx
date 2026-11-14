interface KpiCardProps {
  label: string;
  value: string | number;
  tone?: "default" | "danger" | "warning" | "ok";
}

const TONE_CLASSES: Record<NonNullable<KpiCardProps["tone"]>, string> = {
  default: "text-slate-100",
  danger: "text-centinela-danger",
  warning: "text-centinela-warning",
  ok: "text-centinela-ok",
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

export default function KpiCard({ label, value, tone = "default" }: KpiCardProps) {
  return (
    <div className="rounded-lg border border-slate-800 bg-centinela-panel p-5">
      <p className="text-sm uppercase tracking-wide text-slate-400">{label}</p>
      <p
        className={`mt-2 font-bold leading-tight ${valueSizeClass(value)} ${TONE_CLASSES[tone]}`}
      >
        {value}
      </p>
    </div>
  );
}
