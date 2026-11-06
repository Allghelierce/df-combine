import { ReactNode, useState } from "react";
import type { CveComponentResult, CveEntry, CveLookupDetails, ToolRun } from "../lib/api";
import { formatDate, plural } from "../lib/format";
import { Empty, SeverityBadge, SeverityCounts } from "./ui";

/** Groups with more CVEs than this start collapsed. */
const GROUP_LIMIT = 25;
/** Exploit-DB links shown per CVE before "+N more". */
const EXPLOIT_LINK_LIMIT = 3;

/** Details of a completed `cve_lookup` run, or null when it did not complete or reported nothing usable. */
export function cveDetails(run: ToolRun | undefined): CveLookupDetails | null {
  if (run?.status !== "completed") return null;
  const d = run.details as Partial<CveLookupDetails> | undefined;
  return d?.totals && Array.isArray(d.components) ? (d as CveLookupDetails) : null;
}

/** Renders `backtick` spans in a tool message as code. */
function withCode(text: string): ReactNode[] {
  return text.split("`").map((part, i) => (i % 2 ? <code key={i}>{part}</code> : part));
}

const label = (c: CveComponentResult) => `${c.name} ${c.version}`;

export function CveTable({ run, running }: { run: ToolRun | undefined; running: boolean }) {
  if (!run) return <Empty>{running ? "CVE results appear when the scan completes." : "CVE lookup did not run for this scan."}</Empty>;

  const d = cveDetails(run);
  if (!d) {
    return (
      <div className="warn-box">
        CVE lookup {run.status}
        {run.message ? <>: {withCode(run.message)}</> : "."}
      </div>
    );
  }

  const { db, totals, components } = d;
  const affected = components.filter((c) => c.cves.length > 0);
  const clean = components.filter((c) => c.mapped && c.cves.length === 0);
  const unmapped = components.filter((c) => !c.mapped);

  return (
    <div className="cve">
      {totals.cves > 0 ? (
        <>
          <p className="summary">
            {plural(totals.cves, "known CVE")} in {plural(affected.length, "component")}:{" "}
            <SeverityCounts counts={{ critical: totals.critical, high: totals.high, medium: totals.medium, low: totals.low }} />
          </p>
          <p>
            <span className={totals.known_exploited ? "tone-bad" : undefined}>{totals.known_exploited} actively exploited</span>{" "}
            <span className="muted">(CISA KEV)</span>, <span className={totals.public_exploit ? "sev-high" : undefined}>{totals.public_exploit} with a public exploit</span>
          </p>
        </>
      ) : (
        <p className="summary">
          {totals.components > 0
            ? `No known CVEs matched the ${plural(totals.components, "identified component")}.`
            : "No software components were identified, so there was nothing to look up."}
        </p>
      )}

      {db && (
        <p className="muted">
          CVE database built {formatDate(db.built_at)} from NVD data as of {formatDate(db.nvd_timestamp)} ({db.cve_count.toLocaleString()} CVEs).
        </p>
      )}
      {db?.stale && (
        <div className="warn-box">
          The CVE database is {plural(db.age_days, "day")} old, so CVEs published since then are missing. Rebuild it with <code>make cve-db</code>.
        </div>
      )}
      <p className="muted">
        Matches are based on component version strings and are not verified. Vendors often backport fixes without changing the version, so check each CVE
        against the actual build before acting on it.
      </p>

      {affected.map((c) => (
        <CveGroup key={`${c.name}@${c.version}`} component={c} />
      ))}

      {(clean.length > 0 || unmapped.length > 0) && (
        <p className="muted cve-checked">
          {clean.length > 0 && `No known CVEs: ${clean.map(label).join(", ")}.`}
          {clean.length > 0 && unmapped.length > 0 && " "}
          {unmapped.length > 0 && `No CVE mapping, so not checked: ${unmapped.map(label).join(", ")}.`}
        </p>
      )}
    </div>
  );
}

function CveGroup({ component: c }: { component: CveComponentResult }) {
  const [all, setAll] = useState(false);
  const shown = all ? c.cves : c.cves.slice(0, GROUP_LIMIT);
  return (
    <section className="cve-group">
      <h3>
        {c.name} <span className="mono">{c.version}</span> — {plural(c.cves.length, "CVE")}{" "}
        <span className="muted" title={c.cpe.length ? `CPE: ${c.cpe.join(", ")}` : undefined}>
          {c.method}
        </span>
      </h3>
      <div className="table-scroll">
        <table className="table cve-table">
          <thead>
            <tr>
              <th>CVE</th>
              <th className="num">Score</th>
              <th>Severity</th>
              <th>Exploitation</th>
              <th>Published</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((v) => (
              <CveRow key={v.id} cve={v} />
            ))}
          </tbody>
        </table>
      </div>
      {c.cves.length > GROUP_LIMIT && (
        <button type="button" className="btn cve-more" aria-expanded={all} onClick={() => setAll(!all)}>
          {all ? `Show first ${GROUP_LIMIT}` : `Show all ${c.cves.length}`}
        </button>
      )}
    </section>
  );
}

function CveRow({ cve: v }: { cve: CveEntry }) {
  return (
    <tr>
      <td className="nowrap">
        <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.id)}`} target="_blank" rel="noreferrer">
          {v.id}
        </a>
        {v.match === "cna" && (
          <span className="cve-note" title="Matched on affected versions published by the vendor (CNA), not on NVD configuration data. Lower confidence.">
            vendor data
          </span>
        )}
      </td>
      <td className="num nowrap">
        {v.score !== null ? v.score.toFixed(1) : "–"}
        {v.score !== null && v.cvss_version && <span className="cve-note">CVSS {v.cvss_version}</span>}
      </td>
      <td className="nowrap">
        <SeverityBadge severity={v.severity} />
        {v.score === null && <span className="cve-note">no CVSS score</span>}
      </td>
      <td>
        <ExploitBadges cve={v} />
      </td>
      <td className="nowrap">{v.published ? v.published.slice(0, 10) : "–"}</td>
      <td className="cve-summary">{v.summary}</td>
    </tr>
  );
}

function ExploitBadges({ cve: v }: { cve: CveEntry }) {
  const n = v.exploits.length;
  if (!v.kev && !v.ransomware && n === 0) return <span className="muted">–</span>;
  return (
    <>
      {v.kev && (
        <span className="badge badge-exploited" title="Listed in the CISA Known Exploited Vulnerabilities catalog">
          Exploited
        </span>
      )}
      {v.ransomware && (
        <span className="badge badge-exploited" title="Known to be used in ransomware campaigns (CISA KEV)">
          Ransomware
        </span>
      )}
      {n > 0 && (
        <>
          <span className="badge badge-exploit" title="Public exploit code exists (Exploit-DB)">
            {n > 1 ? `Exploit ×${n}` : "Exploit"}
          </span>
          <span className="cve-note">
            {v.exploits.slice(0, EXPLOIT_LINK_LIMIT).map((e, i) => (
              <span key={e}>
                {i > 0 && ", "}
                <a href={`https://www.exploit-db.com/exploits/${encodeURIComponent(e)}`} target="_blank" rel="noreferrer">
                  EDB-{e}
                </a>
              </span>
            ))}
            {n > EXPLOIT_LINK_LIMIT && ` +${n - EXPLOIT_LINK_LIMIT} more`}
          </span>
        </>
      )}
    </>
  );
}
