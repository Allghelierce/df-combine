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
  /** Installed package owning the affected file (from the package manager's file lists), e.g. "openssh-server 1:8.4p1-5". */
  package?: string | null;
}

export interface VulnRef {
  id: string;
  severity: string | null;
  score: number | null;
  fixed: string | null;
  aliases: string[];
  source: string;
}

export interface PackageItem {
  name: string;
  version: string;
  manager: string;
  source?: string | null;
  source_version?: string | null;
  arch?: string | null;
  database?: string;
  purl?: string;
  owned_files?: number | null;
  vulnerabilities?: VulnRef[];
}

export interface PackageInventory {
  distro: { id: string; version_id: string; codename?: string; name?: string } | null;
  managers: { type: string; database: string; count: number }[];
  total: number;
  items: PackageItem[];
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
  variant?: string | null;
  vulnerabilities?: VulnRef[];
  vulnerabilities_note?: string;
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
  packages?: { distro: PackageInventory["distro"]; managers: PackageInventory["managers"]; count: number; vulnerable: number } | null;
  severity_counts: Record<Severity, number> | null;
  classification_counts: Record<Classification, number> | null;
  risk_score: number | null;
  tool_runs?: ToolRun[];
  events?: ScanEvent[];
  finding_count?: number;
  previous_scans_same_hash?: number;
  can_modify?: boolean;
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
  auth_mode: string;
  role: "admin" | "analyst" | "viewer";
}

export interface Stats {
  scans: Record<string, number>;
  total_scans: number;
  findings_by_severity: Record<string, number>;
  findings_by_classification: Record<string, number>;
  platforms: Record<string, number>;
}

export type ExportKind = "json" | "pdf" | "sarif" | "sbom";
export const EXPORTS: Record<ExportKind, { path: string; suffix: string; label: string }> = {
  pdf: { path: "report.pdf", suffix: "-report.pdf", label: "PDF report" },
  json: { path: "report.json", suffix: "-report.json", label: "JSON" },
  sarif: { path: "report.sarif", suffix: ".sarif", label: "SARIF" },
  sbom: { path: "sbom.cdx.json", suffix: "-sbom.cdx.json", label: "SBOM (CycloneDX)" },
};

/** Session auth uses an HttpOnly cookie; state-changing requests carry this header (CSRF protection). */
const CSRF = { "X-DFA-CSRF": "1" };

function headers(method = "GET"): HeadersInit {
  return method === "GET" || method === "HEAD" ? {} : CSRF;
}

export interface User {
  id: number;
  username: string;
  role: "admin" | "analyst" | "viewer";
  disabled: boolean;
  created_at: string | null;
  last_login_at: string | null;
}

export interface Me {
  user: User | null;
  role: "admin" | "analyst" | "viewer";
  via: string;
  auth_mode: string;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers: { ...headers(init.method ?? "GET"), ...(init.body && !(init.body instanceof FormData) ? { "Content-Type": "application/json" } : {}), ...(init.headers ?? {}) },
  });
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    window.dispatchEvent(new Event("dfa:unauthorized"));
  }
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
  authStatus: () => request<{ auth_mode: string; setup_required: boolean }>("/api/auth/status"),
  me: () => request<Me>("/api/auth/me"),
  login: (username: string, password: string) =>
    request<{ user: User }>("/api/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  logout: () => request<{ status: string }>("/api/auth/logout", { method: "POST" }),
  users: () => request<{ items: User[] }>("/api/users"),
  createUser: (username: string, password: string, role: string) =>
    request<User>("/api/users", { method: "POST", body: JSON.stringify({ username, password, role }) }),
  updateUser: (id: number, patch: Partial<{ role: string; disabled: boolean; password: string }>) =>
    request<User>(`/api/users/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  tokens: () =>
    request<{ items: { id: number; label: string; created_at: string; expires_at: string | null; last_used_at: string | null }[] }>(
      "/api/auth/tokens",
    ),
  createToken: (label: string, days: number) =>
    request<{ token: string; id: number; expires_at: string }>("/api/auth/tokens", {
      method: "POST",
      body: JSON.stringify({ label, days }),
    }),
  revokeToken: (id: number) => request<void>(`/api/auth/tokens/${id}`, { method: "DELETE" }),
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
  packages: (id: string, params: { vulnerable?: boolean; q?: string } = {}) => {
    const qs = new URLSearchParams({ limit: "20000" });
    if (params.vulnerable) qs.set("vulnerable", "true");
    if (params.q) qs.set("q", params.q);
    return request<PackageInventory>(`/api/scans/${encodeURIComponent(id)}/packages?${qs}`);
  },
  rescan: (id: string) => request<{ status: string }>(`/api/scans/${encodeURIComponent(id)}/rescan`, { method: "POST" }),
  remove: (id: string) => request<void>(`/api/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),

  upload(file: File, onProgress?: (pct: number) => void): Promise<Scan> {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/scans");
      xhr.withCredentials = true;
      xhr.setRequestHeader("X-DFA-CSRF", "1");
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

  async download(id: string, kind: ExportKind): Promise<void> {
    const res = await fetch(`/api/scans/${encodeURIComponent(id)}/${EXPORTS[kind].path}`, { credentials: "same-origin" });
    if (!res.ok) throw new ApiError(res.status, `Report download failed (HTTP ${res.status})`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `dfa-${id.slice(0, 8)}${EXPORTS[kind].suffix}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  },
};
