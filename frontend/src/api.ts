const BASE = import.meta.env.VITE_API_BASE ?? '/api'

export interface Project { id: string; name: string; description: string; created_at: string }
export interface Target { id: string; value: string; target_type: string }
export interface ScopeRule { id: string; pattern: string; rule_type: 'ALLOW' | 'DENY'; comment: string }
export interface Asset {
  id: string
  asset_type: 'domain' | 'subdomain' | 'ip' | 'url'
  value: string
  scope_status: 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'UNKNOWN'
  priority_score: number
  priority_reasons: { reason: string; points?: number; ports?: number[]; indicator?: string }[]
  first_seen: string
  last_seen: string
  extra_data: Record<string, unknown>
}
export interface Scan {
  id: string
  project_id: string
  profile: string
  status: string
  stats: Record<string, any>
  error: string | null
  started_at: string | null
  finished_at: string | null
}
export interface GraphNode { id: string; label: string; node_type: string; scope_status: string; score: number }
export interface GraphEdge { src: string; dst: string; rel_type: string }
export interface GraphOut { nodes: GraphNode[]; edges: GraphEdge[] }
export interface Statistics {
  assets: number; domains: number; subdomains: number; ips: number; urls: number
  open_ports: number; technologies: number; findings: number
  high_priority_assets: number; scans_total: number; last_scan_status: string | null
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}: ${await resp.text()}`)
  if (resp.status === 204) return undefined as T
  return resp.json()
}

export const api = {
  listProjects: () => req<Project[]>('/projects'),
  createProject: (name: string, description = '') =>
    req<Project>('/projects', { method: 'POST', body: JSON.stringify({ name, description }) }),
  getProject: (pid: string) => req<Project>(`/projects/${pid}`),

  listTargets: (pid: string) => req<Target[]>(`/projects/${pid}/targets`),
  addTargets: (pid: string, values: { value: string; target_type: string }[]) =>
    req<Target[]>(`/projects/${pid}/targets`, { method: 'POST', body: JSON.stringify(values) }),
  listScope: (pid: string) => req<ScopeRule[]>(`/projects/${pid}/scope`),
  addScopeRules: (pid: string, rules: { pattern: string; rule_type: string; comment?: string }[]) =>
    req<ScopeRule[]>(`/projects/${pid}/scope`, { method: 'POST', body: JSON.stringify(rules) }),

  startScan: (pid: string, profile: string) =>
    req<Scan>(`/projects/${pid}/scans`, { method: 'POST', body: JSON.stringify({ profile }) }),
  listScans: (pid: string) => req<Scan[]>(`/projects/${pid}/scans`),
  stopScan: (scanId: string) => req<Scan>(`/scans/${scanId}/stop`, { method: 'POST' }),

  listAssets: (pid: string, params: Record<string, string> = {}) => {
    const q = new URLSearchParams(params).toString()
    return req<Asset[]>(`/projects/${pid}/assets${q ? `?${q}` : ''}`)
  },
  statistics: (pid: string) => req<Statistics>(`/projects/${pid}/statistics`),
  graph: (pid: string) => req<GraphOut>(`/projects/${pid}/graph`),
  reportUrl: (pid: string, format: string) => `${BASE}/projects/${pid}/report?format=${format}`,
}
