import type {
  AlertaPublica,
  AuditVerification,
  CentinelaEvent,
  Indicadores,
  QuarantinedIp,
  Stats,
} from "./types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:3000";
const API_KEY = import.meta.env.VITE_API_KEY ?? "";

async function getJson<T>(path: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  const response = await fetch(`${API_BASE_URL}${path}`, { headers });
  if (!response.ok) {
    throw new Error(`${path} respondió ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => getJson<{ status: string; service: string; time: string }>("/api/health"),
  stats: () => getJson<Stats>("/api/stats"),
  events: (params: Record<string, string> = {}) => {
    const query = new URLSearchParams(params).toString();
    return getJson<CentinelaEvent[]>(`/api/events${query ? `?${query}` : ""}`);
  },
  blocklist: () => getJson<QuarantinedIp[]>("/api/blocklist"),
  auditVerify: () => getJson<AuditVerification>("/api/audit/verify"),
  publicIndicadores: () => getJson<Indicadores>("/api/public/indicadores"),
  publicAlertas: () => getJson<AlertaPublica[]>("/api/public/alertas"),
};

/** Suscribe al stream SSE de eventos en vivo (/api/stream). */
export function subscribeToStream(onEvent: (event: CentinelaEvent) => void): () => void {
  const source = new EventSource(`${API_BASE_URL}/api/stream`);

  source.addEventListener("centinela_event", (message) => {
    onEvent(JSON.parse((message as MessageEvent).data) as CentinelaEvent);
  });

  return () => source.close();
}
