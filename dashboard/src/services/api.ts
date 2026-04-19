import axios from "axios";

// ─── API Client ──────────────────────────────────────────────────────────────

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080/api/v1",
  timeout: 10_000,
  headers: { "Content-Type": "application/json" },
});

// ─── Types ───────────────────────────────────────────────────────────────────

export interface Incident {
  id: number;
  detected_at: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  attack_type: string;
  confidence: number;
  inference_us: number;
  flow_id: string;
  status: string;
  blocked_at?: string | null;
  notes?: string | null;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface AttackTypeStat {
  attack_type: string;
  count: number;
  avg_confidence: number;
}

export interface TimelineBucket {
  hour: string;
  count: number;
}

export interface ProtocolStat {
  protocol: number;
  protocol_name: string;
  count: number;
}

export interface SummaryResponse {
  total_incidents: number;
  open_incidents: number;
  top_attack_types: AttackTypeStat[];
  recent_timeline: TimelineBucket[];
  protocol_breakdown: ProtocolStat[];
}

// ─── Fetch Functions ─────────────────────────────────────────────────────────

export async function fetchSummary(): Promise<SummaryResponse> {
  const { data } = await api.get<SummaryResponse>("/stats/summary");
  return data;
}

export interface IncidentFilters {
  limit?: number;
  offset?: number;
  label?: string;
  src_ip?: string;
  status?: string;
}

export async function fetchIncidents(
  filters: IncidentFilters = {}
): Promise<PaginatedResponse<Incident>> {
  const params: Record<string, string | number> = {};
  if (filters.limit) params.limit = filters.limit;
  if (filters.offset !== undefined) params.offset = filters.offset;
  if (filters.label) params.label = filters.label;
  if (filters.src_ip) params.src_ip = filters.src_ip;
  if (filters.status) params.status = filters.status;

  const { data } = await api.get<PaginatedResponse<Incident>>("/incidents", {
    params,
  });
  return data;
}

export default api;
