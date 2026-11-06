import { SEVERITIES, Severity } from "./api";

export type SeverityCountMap = Partial<Record<Severity, number>> | null | undefined;

/** Non-zero severities, most severe first. */
export function severityParts(counts: SeverityCountMap): { severity: Severity; n: number }[] {
  return SEVERITIES.map((severity) => ({ severity, n: counts?.[severity] ?? 0 })).filter((p) => p.n > 0);
}

/** "23 findings: 3 critical, 6 high, 10 medium, 4 low" */
export function findingsSummary(counts: SeverityCountMap): string {
  const parts = severityParts(counts);
  const total = parts.reduce((a, p) => a + p.n, 0);
  if (!total) return "No findings";
  return `${total} finding${total === 1 ? "" : "s"}: ${parts.map((p) => `${p.n} ${p.severity}`).join(", ")}`;
}

/** "1 link", "3 links" */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

export function capitalize(s: string): string {
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}

export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "-";
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`;
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function formatDuration(start: string | null | undefined, end: string | null | undefined): string {
  if (!start) return "-";
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const secs = Math.max(0, Math.round((e - s) / 1000));
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  return `${m}m ${secs % 60}s`;
}

export function shortHash(h: string | null | undefined, n = 12): string {
  return h ? `${h.slice(0, n)}…` : "-";
}

export function riskLabel(score: number | null | undefined): { label: string; tone: string } {
  if (score === null || score === undefined) return { label: "n/a", tone: "muted" };
  if (score >= 75) return { label: "Critical", tone: "critical" };
  if (score >= 50) return { label: "High", tone: "high" };
  if (score >= 25) return { label: "Elevated", tone: "medium" };
  if (score > 0) return { label: "Low", tone: "low" };
  return { label: "Minimal", tone: "info" };
}

export function toolStatusTone(status: string): string {
  switch (status) {
    case "completed":
      return "ok";
    case "skipped":
      return "muted";
    case "unavailable":
      return "warn";
    case "failed":
    case "timeout":
      return "bad";
    default:
      return "muted";
  }
}

export const CLASSIFICATION_HELP: Record<string, string> = {
  detected: "Deterministic evidence was found in the image. Exploitability is not verified.",
  suspicious: "Heuristic / pattern match. May be a false positive.",
  unverified: "Needs manual verification (version-based match or static-analysis warning).",
  info: "Informational context.",
};
