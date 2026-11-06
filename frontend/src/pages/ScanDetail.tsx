import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { cveDetails, CveTable } from "../components/CveTable";
import { FindingsTable } from "../components/FindingsTable";
import { CopyText, Empty, ErrorBox, Section, StatusBadge, usePolling } from "../components/ui";
import { api, Artifact, Finding, Scan, ToolRun } from "../lib/api";
import { capitalize, findingsSummary, formatBytes, formatDate, formatDuration, plural, riskLabel, toolStatusTone } from "../lib/format";

type Tab = "findings" | "vulns" | "details" | "inventory" | "components" | "log";

interface Step {
  key: string;
  label: string;
  state: "done" | "active" | "pending" | "failed" | "skipped" | "unavailable";
  note?: string;
}

export function pipelineSteps(scan: Scan): Step[] {
  const runs = scan.tool_runs ?? [];
  const byTool = (t: string) => runs.find((r) => r.tool === t);
  const builtin = runs.filter((r) => r.tool.startsWith("builtin"));
  const failed = scan.status === "failed";
  const sandboxDone = builtin.length > 0 && builtin.every((r) => r.status !== "running");
  const steps: Step[] = [
    { key: "upload", label: "Upload", state: "done" },
    {
      key: "sandbox",
      label: "Built-in checks",
      state: sandboxDone
        ? builtin.some((r) => r.status === "failed")
          ? "failed"
          : "done"
        : failed
          ? "failed"
          : scan.status === "running"
            ? "active"
            : "pending",
    },
  ];
  for (const [tool, label] of [
    ["cve_lookup", "CVE lookup"],
    ["fwanalyzer", "FwAnalyzer"],
    ["cwe_checker", "cwe_checker"],
  ] as const) {
    const r = byTool(tool);
    let state: Step["state"] = "pending";
    if (r) state = r.status === "completed" ? "done" : r.status === "skipped" ? "skipped" : r.status === "unavailable" ? "unavailable" : "failed";
    else if (scan.stage === `tool:${tool}`) state = "active";
    else if (failed) state = "skipped";
    steps.push({ key: tool, label, state, note: r?.status });
  }
  steps.push({
    key: "report",
    label: "Report",
    state: scan.status === "completed" ? "done" : failed ? "failed" : "pending",
  });
  return steps;
}

const STEP_WORD: Record<Step["state"], string> = {
  done: "done",
  active: "running",
  pending: "waiting",
  failed: "failed",
  skipped: "skipped",
  unavailable: "unavailable",
};

export default function ScanDetail() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [artifacts, setArtifacts] = useState<Awaited<ReturnType<typeof api.artifacts>> | null>(null);
  const [tab, setTab] = useState<Tab>("findings");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const running = scan?.status === "queued" || scan?.status === "running";

  const load = useCallback(() => {
    api
      .scan(id)
      .then((s) => {
        setScan(s);
        setError(null);
        if (s.status === "completed" || s.status === "failed") {
          api.findings(id).then((f) => setFindings(f.items)).catch(setError);
          api.artifacts(id).then(setArtifacts).catch(() => undefined);
        }
      })
      .catch(setError);
  }, [id]);

  useEffect(() => {
    setFindings(null);
    setArtifacts(null);
    load();
  }, [load]);
  usePolling(load, 1500, running);

  async function act(kind: "json" | "pdf" | "rescan" | "delete") {
    setBusy(kind);
    try {
      if (kind === "json" || kind === "pdf") await api.download(id, kind);
      if (kind === "rescan") {
        await api.rescan(id);
        setFindings(null);
        load();
      }
      if (kind === "delete") {
        if (!window.confirm("Delete this scan, its uploaded firmware and all results?")) return;
        await api.remove(id);
        navigate("/scans");
      }
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  }

  if (!scan) {
    return (
      <div className="page">
        <ErrorBox error={error} />
        {!error && <Empty>Loading scan…</Empty>}
      </div>
    );
  }

  const ident = scan.identification;
  const tools = pipelineSteps(scan).filter((s) => s.key !== "upload" && s.key !== "report");
  const cveRun = scan.tool_runs?.find((r) => r.tool === "cve_lookup");
  const cve = cveDetails(cveRun);
  const lastEvent = scan.events?.length ? scan.events[scan.events.length - 1].message : "Waiting for a worker";
  return (
    <div className="page">
      <div className="crumbs">
        <Link to="/scans">Scans</Link> / <span className="mono">{scan.id.slice(0, 8)}</span>
      </div>
      <header className="page-head">
        <div>
          <h1 className="break">{scan.original_filename}</h1>
          <p className="meta">
            <StatusBadge status={scan.status} />, {formatBytes(scan.size)}, uploaded {formatDate(scan.created_at)}
            {scan.finished_at && `, took ${formatDuration(scan.started_at, scan.finished_at)}`}
          </p>
        </div>
        <div className="actions">
          <button className="btn primary" disabled={scan.status !== "completed" || !!busy} onClick={() => act("pdf")}>
            {busy === "pdf" ? "Generating…" : "Export PDF"}
          </button>
          <button className="btn" disabled={!!busy || running} onClick={() => act("json")}>
            Export JSON
          </button>
          <button className="btn" disabled={running || !!busy} onClick={() => act("rescan")}>
            Re-scan
          </button>
          <button className="btn danger" disabled={scan.status === "running" || !!busy} onClick={() => act("delete")}>
            Delete
          </button>
        </div>
      </header>
      <ErrorBox error={error} />

      <div className="scan-summary">
        {scan.status === "completed" && <p className="summary">{findingsSummary(scan.severity_counts)}</p>}
        {ident && (
          <p>
            {ident.platform}, {ident.format_description}
            {ident.architecture ? `, ${ident.architecture}` : ""}
          </p>
        )}
        <ul className="tool-line" aria-label="Analysis tools">
          {tools.map((s) => (
            <li key={s.key} title={s.note}>
              {s.label}: <span className={`state-${s.state}`}>{STEP_WORD[s.state]}</span>
            </li>
          ))}
        </ul>
        {running && (
          <div className="live">
            <div className="progress" role="progressbar" aria-valuenow={scan.progress} aria-valuemin={0} aria-valuemax={100}>
              <span style={{ width: `${Math.max(scan.progress, 3)}%` }} />
            </div>
            <p className="muted">
              {scan.progress}%: {lastEvent}
            </p>
          </div>
        )}
        {scan.status === "failed" && <div className="error-box">Scan failed: {scan.error}</div>}
      </div>

      <div className="tabs" role="tablist">
        {(
          [
            ["findings", `Findings${findings ? ` (${findings.length})` : ""}`],
            ["vulns", `Vulnerabilities${cve ? ` (${cve.totals.cves})` : ""}`],
            ["details", "Details"],
            ["inventory", `Files${artifacts ? ` (${artifacts.total})` : ""}`],
            ["components", `Components (${scan.components?.length ?? 0})`],
            ["log", "Activity log"],
          ] as [Tab, string][]
        ).map(([k, label]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>
            {label}
          </button>
        ))}
      </div>

      {tab === "findings" && (findings ? <FindingsTable findings={findings} /> : <Empty>{running ? "Findings appear when the scan completes." : "Loading…"}</Empty>)}
      {tab === "vulns" && <CveTable run={cveRun} running={running} />}
      {tab === "details" && <Details scan={scan} />}
      {tab === "inventory" && <Inventory data={artifacts} running={running} />}
      {tab === "components" && <Components scan={scan} />}
      {tab === "log" && <ActivityLog scan={scan} />}
    </div>
  );
}

function Details({ scan }: { scan: Scan }) {
  const ident = scan.identification;
  const ex = scan.extraction_summary;
  const risk = riskLabel(scan.risk_score);
  return (
    <>
      <Section title="Firmware">
        <CopyText text={scan.sha256} display={`SHA-256 ${scan.sha256}`} />
        {ident ? (
          <>
            <dl className="kv">
              <dt>Platform</dt>
              <dd>
                {ident.platform}
                {ident.platform_confidence && <span className="muted"> ({ident.platform_confidence} confidence)</span>}
              </dd>
              <dt>Format</dt>
              <dd>{ident.format_description}</dd>
              <dt>Architecture</dt>
              <dd>
                {[ident.architecture ?? "unknown", ident.bits ? `${ident.bits}-bit` : null, ident.endianness ? `${ident.endianness}-endian` : null]
                  .filter(Boolean)
                  .join(", ")}
              </dd>
              <dt>OS</dt>
              <dd>{ident.os_hint ?? "unknown"}</dd>
              <dt>Version</dt>
              <dd className="mono">{ident.platform_version ?? "–"}</dd>
              {ident.vehicle_type && (
                <>
                  <dt>Vehicle</dt>
                  <dd>{ident.vehicle_type}</dd>
                </>
              )}
              {ident.board_id !== null && ident.board_id !== undefined && (
                <>
                  <dt>Board ID</dt>
                  <dd>
                    {ident.board_id}
                    {ident.board_hint ? ` (${ident.board_hint})` : ""}
                  </dd>
                </>
              )}
              <dt>Entropy</dt>
              <dd>{ident.entropy.toFixed(2)} bits per byte</dd>
              <dt>Isolation</dt>
              <dd>{ex?.isolation_detail ?? scan.isolation ?? "–"}</dd>
              <dt>Risk score</dt>
              <dd>
                {scan.risk_score ?? "–"}
                {scan.risk_score !== null && ` of 100, ${risk.label.toLowerCase()}`}
                <span className="muted"> (a heuristic from severity and evidence, not a probability)</span>
              </dd>
            </dl>
            {ident.platform_candidates.length > 0 && (
              <details>
                <summary>Why this platform ({plural(ident.platform_candidates.length, "candidate")})</summary>
                <ul>
                  {ident.platform_candidates.map((c) => (
                    <li key={c.name}>
                      {c.name} <span className="muted">(score {c.score}, {c.confidence})</span>
                      <div className="mono muted">{c.evidence.join("; ")}</div>
                    </li>
                  ))}
                </ul>
              </details>
            )}
            {ident.ardupilot_descriptor && <KeyValues summary="ArduPilot app descriptor" data={ident.ardupilot_descriptor} />}
            {Object.keys(ident.container_metadata ?? {}).length > 0 && <KeyValues summary="Container metadata" data={ident.container_metadata} />}
          </>
        ) : (
          <Empty>Identification is available once the built-in checks finish.</Empty>
        )}
      </Section>

      <Section title="Extraction">
        {ex ? (
          <>
            <p>
              {plural(ex.artifact_count, "file")} extracted from {plural(ex.filesystems.length, "container or filesystem", "containers or filesystems")}.{" "}
              {ex.link_count > 0 && `${plural(ex.link_count, "link")} recorded but not followed.`}
            </p>
            <p className="muted">
              {Object.entries(ex.categories)
                .map(([k, v]) => `${k.replace("_", " ")}: ${v}`)
                .join(", ")}
            </p>
            {ex.limits_hit.length > 0 && <div className="warn-box">Limits reached: {ex.limits_hit.join("; ")}</div>}
            {ex.warnings.length > 0 && (
              <details>
                <summary>{plural(ex.warnings.length, "extraction warning")}</summary>
                <ul className="mono">
                  {ex.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              </details>
            )}
          </>
        ) : (
          <Empty>Pending.</Empty>
        )}
      </Section>

      <Section title="Tool runs">
        <ToolRuns runs={scan.tool_runs ?? []} />
      </Section>
    </>
  );
}

function KeyValues({ summary, data }: { summary: string; data: Record<string, unknown> }) {
  return (
    <details>
      <summary>{summary}</summary>
      <dl className="kv mono">
        {Object.entries(data).map(([k, v]) => (
          <div key={k} className="kv-row">
            <dt>{k}</dt>
            <dd>{String(v)}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

function ToolRuns({ runs }: { runs: ToolRun[] }) {
  if (!runs.length) return <Empty>No tool has reported yet.</Empty>;
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Tool</th>
          <th>Status</th>
          <th className="num">Findings</th>
          <th className="num">Time</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {runs.map((r, i) => (
          <tr key={i}>
            <td className="nowrap">{r.display_name}</td>
            <td className={`tone-${toolStatusTone(r.status)}`}>{capitalize(r.status)}</td>
            <td className="num">{r.findings_count}</td>
            <td className="num">{r.duration_s !== null ? `${r.duration_s.toFixed(1)}s` : "–"}</td>
            <td className="muted">{r.message}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Inventory({ data, running }: { data: Awaited<ReturnType<typeof api.artifacts>> | null; running: boolean }) {
  const [cat, setCat] = useState("");
  const [q, setQ] = useState("");
  const cats = useMemo(() => Array.from(new Set((data?.items ?? []).map((a) => a.category))).sort(), [data]);
  if (!data) return <Empty>{running ? "The file list appears when extraction completes." : "Loading…"}</Empty>;
  const items = data.items.filter((a: Artifact) => (!cat || a.category === cat) && (!q || a.display_path.toLowerCase().includes(q.toLowerCase())));
  return (
    <>
      <div className="filters">
        <span className="filter">
          <label htmlFor="inv-cat">Category</label>
          <select id="inv-cat" value={cat} onChange={(e) => setCat(e.target.value)}>
            <option value="">All</option>
            {cats.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </span>
        <input type="search" placeholder="Filter by path" aria-label="Filter by path" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="muted count">
          {items.length} of {data.total}
        </span>
      </div>
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              <th>Path</th>
              <th>Category</th>
              <th>Format</th>
              <th className="num">Size</th>
              <th>Architecture and hardening</th>
              <th>Mode</th>
            </tr>
          </thead>
          <tbody>
            {items.slice(0, 1500).map((a) => {
              const elf = a.elf as Record<string, string | boolean | null> | undefined;
              return (
                <tr key={a.id}>
                  <td className="mono path" style={{ paddingLeft: `${8 + a.depth * 14}px` }} title={a.display_path}>
                    {a.name}
                    {a.extraction && a.extraction !== "ok" && <span className={a.extraction === "failed" ? "tone-bad" : "tone-warn"}> ({a.extraction})</span>}
                  </td>
                  <td>{a.category}</td>
                  <td>{a.format_description}</td>
                  <td className="num nowrap">{formatBytes(a.size)}</td>
                  <td>
                    {elf ? (
                      <>
                        {String(elf.arch)}
                        {elf.os_hint === "linux" && elf.interpreter ? (
                          <span className="hardening">
                            <span className={elf.nx ? "tone-ok" : "tone-bad"}>NX</span>
                            <span className={elf.pie ? "tone-ok" : "tone-bad"}>PIE</span>
                            <span className={elf.relro === "full" ? "tone-ok" : elf.relro === "partial" ? "tone-warn" : "tone-bad"}>RELRO</span>
                            <span className={elf.canary ? "tone-ok" : "tone-bad"}>Canary</span>
                          </span>
                        ) : null}
                      </>
                    ) : (
                      <span className="muted">–</span>
                    )}
                  </td>
                  <td className="mono">{a.mode !== null && a.mode !== undefined ? a.mode.toString(8).padStart(4, "0") : "–"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {data.link_count > 0 && (
        <details>
          <summary>{data.link_count} symlinks, hardlinks or device entries were recorded but not created (path traversal protection)</summary>
          <ul className="mono">
            {data.links.slice(0, 200).map((l, i) => (
              <li key={i}>
                [{l.kind}] {l.path}
                {l.target ? ` → ${l.target}` : ""}
              </li>
            ))}
          </ul>
        </details>
      )}
    </>
  );
}

function Components({ scan }: { scan: Scan }) {
  const comps = scan.components ?? [];
  if (!comps.length) return <Empty>No software components with recognisable version strings were found.</Empty>;
  return (
    <>
      <p className="muted">Identified from version strings. Verify them before relying on them.</p>
      <table className="table">
        <thead>
          <tr>
            <th>Component</th>
            <th>Version</th>
            <th>Method</th>
            <th>Found in</th>
          </tr>
        </thead>
        <tbody>
          {comps.map((c) => (
            <tr key={`${c.name}-${c.version}`}>
              <td>{c.name}</td>
              <td className="mono">{c.version}</td>
              <td className="muted">{c.method}</td>
              <td className="mono">{c.sources.join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function ActivityLog({ scan }: { scan: Scan }) {
  const ev = scan.events ?? [];
  if (ev.length === 0) return <Empty>No events yet.</Empty>;
  return (
    <table className="table log">
      <tbody>
        {ev.map((e, i) => (
          <tr key={i} className={`lvl-${e.level}`}>
            <td className="mono muted nowrap">{new Date(e.ts).toLocaleTimeString()}</td>
            <td className="muted nowrap">{e.stage}</td>
            <td>{e.message}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
