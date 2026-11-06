export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Classification = "detected" | "suspicious" | "unverified" | "info";
export type ScanStatus = "queued" | "running" | "completed" | "failed";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const CLASSIFICATIONS: Classification[] = ["detected", "suspicious", "unverified", "info"];

export interface Evidence {
  kind: string;
  value: string;
  location?: string | null;
}

export interface Finding {
  id: number;
  fingerprint: string;
  title: string;
  description: string;
  severity: Severity;
  classification: Classification;
  confidence: "high" | "medium" | "low";
  source_tool: string;
  rule_id: string;
  affected_component: string;
  remediation: string;
  evidence: Evidence[];
  cwe: string | null;
  references: string[];
  tags: string[];
}

export interface PlatformCandidate {
  name: string;
  family: string;
  confidence: string;
  score: number;
  evidence: string[];
  version: string | null;
  vehicle: string | null;
}

export interface Identification {
  format: string;
  format_description: string;
  size: number;
  sha256: string;
  entropy: number;
  architecture: string | null;
  bits: number | null;
  endianness: string | null;
  os_hint: string | null;
  platform: string;
  platform_family: string | null;
  platform_confidence: string | null;
  platform_version: string | null;
  vehicle_type: string | null;
  platform_candidates: PlatformCandidate[];
  board_id: number | null;
  board_hint: string | null;
  container_metadata: Record<string, unknown>;
  ardupilot_descriptor?: Record<string, string | number> | null;
  details: Record<string, unknown>;
}

export interface ToolRun {
  tool: string;
  display_name: string;
  status: string;
  message: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_s: number | null;
  findings_count: number;
  details: Record<string, unknown>;
}

/** One CVE matched against a component by the `cve_lookup` tool. */
export interface CveEntry {
  id: string;
  /** CVSS base score; null when NVD has not scored the CVE yet. */
  score: number | null;
  severity: Severity;
  cvss_version: string | null;
  /** Listed in the CISA Known Exploited Vulnerabilities catalog. */
  kev: boolean;
  ransomware: boolean;
  /** Exploit-DB ids. */
  exploits: string[];
  summary: string;
  published: string | null;
  /** "nvd" = NVD configuration match, "cna" = vendor-published affected versions (lower confidence). */
  match: "nvd" | "cna";
}

export interface CveComponentResult {
  name: string;
  version: string;
  method: string;
  /** False when there is no CVE mapping for this component; `cves` is then empty. */
  mapped: boolean;
  cpe: string[];
  /** Already sorted: exploited first, then with exploits, then by score. */
  cves: CveEntry[];
}

export interface CveDatabaseInfo {
  built_at: string;
  nvd_timestamp: string;
  cve_count: number;
  age_days: number;
  stale: boolean;
}

export interface CveTotals {
  components: number;
  cves: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  known_exploited: number;
  public_exploit: number;
}

/** `ToolRun.details` of a completed `cve_lookup` run. */
export interface CveLookupDetails {
  db: CveDatabaseInfo;
  totals: CveTotals;
  components: CveComponentResult[];
}

export interface ScanEvent {
  ts: string;
  level: string;
  stage: string;
  message: string;
}

export interface Component {
  name: string;
  version: string;
  sources: string[];
  method: string;
}

export interface ExtractionSummary {
  artifact_count: number;
  warnings: string[];
  filesystems: { type: string; name: string; root: string }[];
  limits_hit: string[];
  stats: Record<string, unknown>;
  rootfs: string[];
  link_count: number;
  categories: Record<string, number>;
  isolation_detail: string;
}

export interface Scan {
  id: string;
  status: ScanStatus;
  stage: string;
  progress: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  original_filename: string;
  size: number;
  sha256: string;
  isolation: string | null;
  identification: Identification | null;
  extraction_summary: ExtractionSummary | null;
  components: Component[];
  severity_counts: Record<Severity, number> | null;
  classification_counts: Record<Classification, number> | null;
  risk_score: number | null;
  tool_runs?: ToolRun[];
  events?: ScanEvent[];
  finding_count?: number;
  previous_scans_same_hash?: number;
}

export interface Artifact {
  id: number;
  name: string;
  display_path: string;
  size: number;
  sha256: string;
  format: string;
  format_description: string;
  category: string;
  parent_id: number | null;
  depth: number;
  origin: string;
  mode: number | null;
  extraction: string | null;
  extraction_note: string | null;
  elf?: Record<string, unknown>;
}

export interface ToolStatus {
  name: string;
  display_name: string;
  available: boolean;
  detail: string;
  mode: string | null;
  version: string | null;
  enabled: boolean;
  homepage: string | null;
  inputs: string | null;
}

export interface AppConfig {
  version: string;
  max_upload_mb: number;
  sandbox_mode: string;
  sandbox_detail: string;
  worker_mode: string;
  auth_required: boolean;
}

export interface Stats {
  scans: Record<string, number>;
  total_scans: number;
  findings_by_severity: Record<string, number>;
  findings_by_classification: Record<string, number>;
  platforms: Record<string, number>;
}

const KEY_STORAGE = "dfa_api_key";

export function getApiKey(): string | null {
  try {
    return localStorage.getItem(KEY_STORAGE);
  } catch {
    return null;
  }
}

export function setApiKey(key: string | null): void {
  try {
    if (key) localStorage.setItem(KEY_STORAGE, key);
    else localStorage.removeItem(KEY_STORAGE);
  } catch {
    /* storage unavailable */
  }
}

function headers(): HeadersInit {
  const key = getApiKey();
  return key ? { "X-API-Key": key } : {};
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, { ...init, headers: { ...headers(), ...(init.headers ?? {}) } });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, detail || `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export interface Comparison {
  base: Scan;
  target: Scan;
  new: Finding[];
  resolved: Finding[];
  severity_changed: (Finding & { previous_severity: Severity })[];
  unchanged: Finding[];
  components: { name: string; before: string[]; after: string[]; change: "added" | "removed" | "changed" }[];
  summary: Record<string, number>;
}

export const api = {
  compare: (base: string, target: string) =>
    request<Comparison>(`/api/compare?base=${encodeURIComponent(base)}&target=${encodeURIComponent(target)}`),
  config: () => request<AppConfig>("/api/config"),
  stats: () => request<Stats>("/api/stats"),
  tools: () => request<{ tools: ToolStatus[] }>("/api/tools"),
  scans: (params: { q?: string; status?: string; limit?: number; offset?: number } = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== "" && qs.set(k, String(v)));
    return request<{ total: number; items: Scan[] }>(`/api/scans?${qs}`);
  },
  scan: (id: string) => request<Scan>(`/api/scans/${encodeURIComponent(id)}`),
  findings: (id: string) => request<{ items: Finding[] }>(`/api/scans/${encodeURIComponent(id)}/findings`),
  artifacts: (id: string) =>
    request<{ total: number; items: Artifact[]; links: { path: string; kind: string; target: string | null }[]; link_count: number }>(
      `/api/scans/${encodeURIComponent(id)}/artifacts?limit=5000`,
    ),
  rescan: (id: string) => request<{ status: string }>(`/api/scans/${encodeURIComponent(id)}/rescan`, { method: "POST" }),
  remove: (id: string) => request<void>(`/api/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),

  upload(file: File, onProgress?: (pct: number) => void): Promise<Scan> {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/scans");
      const key = getApiKey();
      if (key) xhr.setRequestHeader("X-API-Key", key);
      xhr.upload.onprogress = (e) => e.lengthComputable && onProgress?.(Math.round((100 * e.loaded) / e.total));
      xhr.onload = () => {
        let body: { detail?: string } & Partial<Scan> = {};
        try {
          body = JSON.parse(xhr.responseText);
        } catch {
          /* ignore */
        }
        if (xhr.status === 201) resolve(body as Scan);
        else reject(new ApiError(xhr.status, body.detail ?? `Upload failed (HTTP ${xhr.status})`));
      };
      xhr.onerror = () => reject(new ApiError(0, "Network error during upload"));
      const form = new FormData();
      form.append("file", file);
      xhr.send(form);
    });
  },

  async download(id: string, kind: "json" | "pdf"): Promise<void> {
    const res = await fetch(`/api/scans/${encodeURIComponent(id)}/report.${kind}`, { headers: headers() });
    if (!res.ok) throw new ApiError(res.status, `Report download failed (HTTP ${res.status})`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `dfa-report-${id.slice(0, 8)}.${kind}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  },
};
