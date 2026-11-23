export type ScanType = 'sast' | 'sca' | 'dast'
export type Band = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type BandCounts = Record<Band, number>
export type FindingStatus = 'open' | 'fixed' | 'accepted' | 'false_positive'

export interface Repo {
  id: number
  full_name: string
  default_branch: string
  business_unit: string | null
  owner: string | null
  description: string | null
  criticality: number
  exposure: 'internal' | 'partner' | 'internet'
  data_sensitivity: 'public' | 'internal' | 'confidential' | 'restricted'
  compliance: string[]
  revenue_impacting: boolean
  risk_score: number
  ai_summary: string | null
  ai_summary_at: string | null
  updated_at: string
}

export interface RepoSummary extends Repo {
  open_findings: number
  kev_findings: number
  by_type: Partial<Record<ScanType, number>>
  by_band: BandCounts
  last_scan_at: string | null
}

export interface Finding {
  id: number
  repository_id: number
  repository_name: string | null
  scan_type: ScanType
  tool: string
  rule_id: string | null
  title: string
  description: string | null
  severity: Band
  cwe: string[]
  cve: string | null
  file_path: string | null
  line: number | null
  url: string | null
  package: string | null
  installed_version: string | null
  fixed_version: string | null
  cvss_score: number | null
  epss_score: number | null
  epss_percentile: number | null
  in_kev: boolean
  base_score: number
  ai_adjustment: number
  ai_rationale: string | null
  risk_score: number
  score_factors: Record<string, number | string>
  status: FindingStatus
  first_seen: string
  last_seen: string
  fixed_at: string | null
  sla_days: number | null
}

export interface Scan {
  id: number
  scan_type: ScanType
  tool: string
  format: string
  branch: string | null
  commit_sha: string | null
  workflow_run_url: string | null
  finding_count: number
  new_count: number
  fixed_count: number
  created_at: string
}

export interface Overview {
  repositories: number
  open_findings: number
  kev_findings: number
  portfolio_risk: number
  by_band: BandCounts
  by_type: Partial<Record<ScanType, number>>
  top_findings: Finding[]
  trend: { date: string; open: number }[]
}

const TOKEN_KEY = 'risk-runner-token'

export function getToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) ?? ''
  } catch {
    return ''
  }
}

export function setToken(token: string) {
  try {
    localStorage.setItem(TOKEN_KEY, token)
  } catch {
    /* storage unavailable */
  }
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken()
  const res = await fetch(`/api/v1${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
  })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, detail)
  }
  return res.json() as Promise<T>
}

export interface FindingQuery {
  repo_id?: number
  status?: FindingStatus | ''
  scan_type?: ScanType | ''
  kev?: boolean
  min_score?: number
  q?: string
}

export const api = {
  overview: () => request<Overview>('/overview'),
  repos: () => request<RepoSummary[]>('/repos'),
  repo: (id: number) => request<Repo>(`/repos/${id}`),
  updateRepo: (id: number, body: Partial<Repo>) =>
    request<Repo>(`/repos/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  scans: (id: number) => request<Scan[]>(`/repos/${id}/scans`),
  analyze: (id: number) => request<{ analyzed: number }>(`/repos/${id}/analyze`, { method: 'POST' }),
  findings: (query: FindingQuery = {}) => {
    const params = new URLSearchParams()
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== '' && v !== null) params.set(k, String(v))
    }
    if (query.status === '') params.set('status', 'all')
    return request<Finding[]>(`/findings?${params}`)
  },
  updateFinding: (id: number, status: FindingStatus) =>
    request<Finding>(`/findings/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) }),
  refreshIntel: () => request<{ status: string }>('/intel/refresh', { method: 'POST' }),
}

export function band(score: number): Band {
  if (score >= 85) return 'critical'
  if (score >= 65) return 'high'
  if (score >= 40) return 'medium'
  if (score >= 15) return 'low'
  return 'info'
}

export const BANDS: Band[] = ['critical', 'high', 'medium', 'low', 'info']

export function timeAgo(iso: string | null): string {
  if (!iso) return 'never'
  const s = (Date.now() - new Date(iso).getTime()) / 1000
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}
