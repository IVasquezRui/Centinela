// Tipos que reflejan el contrato de evento congelado en docs/SPRINT-1.md
// (sección 4). No cambiar sin avisar al equipo completo.

export type Severity = "baja" | "media" | "alta" | "critica";

export type Category =
  | "sqli"
  | "xss"
  | "traversal"
  | "cmdi"
  | "scanner"
  | "bruteforce";

export type Verdict = "block" | "allow";

export interface CentinelaEvent {
  id: number;
  ts: string;
  src_ip: string;
  method: string;
  path: string;
  target: string;
  verdict: Verdict;
  rule_id: string | null;
  category: Category | null;
  severity: Severity | null;
  technique_id: string | null;
  ml_score: number | null;
  engine_us: number;
  payload_sample: string | null;
  ai_summary: string | null;
  ai_status: "pending" | "done";
}

export interface Stats {
  total_requests: number;
  blocked_requests: number;
  allowed_requests: number;
  quarantined_ips: number;
  engine_latency_p95_us: number | null;
}

export interface QuarantinedIp {
  ip: string;
  quarantined_for_seconds: number;
}

export interface AuditVerification {
  valid: boolean;
  broken_at_id: number | null;
  entries_checked: number;
}

export interface Indicadores {
  incidentes_ultimos_30_dias: number;
  tipo_amenaza_predominante: string | null;
  sector_mas_afectado: string | null;
  severidad_promedio: Severity | null;
  tendencia: "al_alza" | "a_la_baja" | "estable";
}

export interface AlertaPublica {
  fecha: string;
  descripcion: string;
  severidad: Severity | null;
  recomendacion: string;
}
