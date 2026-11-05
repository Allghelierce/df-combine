import type { BuildInfo, Finding, ImageInfo } from "./api";

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

/** What a finding rests on, so static-analysis warnings and version matches are never read as confirmed vulnerabilities. */
export function findingBasis(f: Pick<Finding, "source_tool" | "rule_id" | "classification" | "tags">): { label: string; text: string } {
  if (f.source_tool === "cwe_checker" || f.source_tool === "ghidra" || f.tags.includes("static-analysis")) {
    return {
      label: "Static-analysis warning",
      text: "Automated analysis of the machine code found this pattern. Reachability and exploitability were not established; it is not a confirmed vulnerability.",
    };
  }
  if (f.rule_id === "osv-distro-package") {
    return {
      label: "Distribution security advisory",
      text: "The installed package version is listed as affected in the distribution's own security data (backported fixes are taken into account). Whether the vulnerable code is used in this firmware was not verified.",
    };
  }
  if (f.rule_id.startsWith("osv-upstream-") || f.rule_id.startsWith("outdated-")) {
    return {
      label: "Version-based match",
      text: "A version string matches affected upstream releases. Vendor backports are invisible to this check, so each entry needs manual confirmation.",
    };
  }
  switch (f.classification) {
    case "detected":
      return { label: "Direct evidence", text: "Concrete evidence is present in the firmware image (file, key, configuration line). Exploitability is not verified." };
    case "suspicious":
      return { label: "Heuristic pattern", text: "Pattern-based detection; it may be a false positive." };
    case "unverified":
      return { label: "Needs verification", text: "Reported by a tool without direct evidence; confirm manually." };
    default:
      return { label: "Context", text: "Informational." };
  }
}

export const CLASSIFICATION_HELP: Record<string, string> = {
  detected: "Deterministic evidence was found in the image. Exploitability is not verified.",
  suspicious: "Heuristic / pattern match. May be a false positive.",
  unverified: "Needs manual verification (version-based match or static-analysis warning).",
  info: "Informational context.",
};

export function buildLine(b: BuildInfo | null | undefined): string | null {
  if (!b) return null;
  const parts = [b.revision ? `git ${b.revision}` : null, b.date ?? null, b.time ?? null].filter(Boolean);
  return parts.length ? parts.join(" · ") : null;
}

export function imageSummary(i: ImageInfo | null | undefined): string | null {
  if (!i) return null;
  const n = (x: number) => x.toLocaleString("en-US");
  const parts: string[] = [];
  // where the artifact came from: content found after other data, or data around it
  if (i.carved_offset) parts.push(`found at ${i.carved_offset}`);
  if (i.prepended_bytes) parts.push(`${n(i.prepended_bytes)} bytes before the archive (e.g. a vendor header)`);
  if (i.trailing_padding_bytes) parts.push(`${n(i.trailing_padding_bytes)} bytes of padding after the data`);
  if (i.trailing_bytes) parts.push(`${n(i.trailing_bytes)} bytes after the data (size field or checksum)`);
  if (!i.flash_base) return parts.length ? shown(parts.join(" · ")) : null;
  parts.push(`load address ${i.flash_base}`);
  if (i.symbol_count) {
    parts.push(
      i.derived_from_elf
        ? `${i.symbol_count.toLocaleString("en-US")} function symbols (derived from the ELF)`
        : `${i.symbol_count.toLocaleString("en-US")} function symbols from ${i.symbols_from || "the build's ELF"}`,
    );
  }
  if (i.identical_to !== undefined && i.identical_to !== null) parts.push(`identical to artifact #${i.identical_to}`);
  return shown(parts.join(" · "));
}

export const INVENTORY_ROWS = 1500;

/** Inventory counter that says when rows are cut off (rendered rows, loaded artifacts). */
export function inventoryCount(matching: number, loaded: number, total: number): string {
  const n = (x: number) => x.toLocaleString("en-US");
  let text = matching > INVENTORY_ROWS ? `showing ${n(INVENTORY_ROWS)} of ${n(matching)} matching` : `${n(matching)} matching`;
  text += ` · ${n(total)} artifacts`;
  if (loaded < total) text += ` (first ${n(loaded)} loaded)`;
  if (matching > INVENTORY_ROWS) text += " — filter to narrow";
  return text;
}

/** The link target for a finding reference, or null when it must be shown as plain text. References can come
 * from the sandbox, which processes hostile firmware, so only absolute http(s) URLs become links. */
export function externalUrl(ref: string): string | null {
  if (!/^https?:\/\//i.test(ref)) return null;
  try {
    const u = new URL(ref);
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : null;
  } catch {
    return null;
  }
}

// controls (tab and newline included), bidirectional overrides/isolates, and characters that render as nothing
// or as blank space: soft hyphen, combining grapheme joiner, Hangul fillers, Khmer/Mongolian invisible vowels and
// separators, zero-width and line/paragraph separators, invisible operators, variation selectors, tag characters
const HIDDEN =
  /[\u0000-\u001f\u007f-\u009f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/gu;

/** Firmware-derived text (names, paths, evidence) as it is: characters that would act instead of showing
 * (U+202E reversing "evil\u202etxt.exe" into "evilexe.txt", zero-width ones, a newline in a name) are
 * displayed as escapes such as \u202e. */
export function shown(text: string | null | undefined): string {
  if (!text) return text ?? "";
  return text.replace(HIDDEN, (c) => {
    const cp = c.codePointAt(0) ?? 0;
    return cp > 0xffff ? `\\u{${cp.toString(16)}}` : `\\u${cp.toString(16).padStart(4, "0")}`;
  });
}
