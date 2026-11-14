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

export default function KpiCard({ label, value, tone = "default" }: KpiCardProps) {
  return (
    <div className="rounded-lg border border-slate-800 bg-centinela-panel p-5">
      <p className="text-sm uppercase tracking-wide text-slate-400">{label}</p>
      <p className={`mt-2 text-3xl font-bold ${TONE_CLASSES[tone]}`}>{value}</p>
    </div>
  );
}
