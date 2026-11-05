import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { RiskGauge, SeverityDonut, StackedBar } from "../components/charts";
import { FindingsTable } from "../components/FindingsTable";
import { CopyText, Empty, ErrorBox, Icon, Panel, StatusBadge, usePolling } from "../components/ui";
import { api, Artifact, ExportKind, EXPORTS, Finding, PackageInventory, PackageItem, Scan, ToolRun, VulnRef } from "../lib/api";
import { buildLine, formatBytes, formatDate, formatDuration, imageSummary, INVENTORY_ROWS, inventoryCount, shown, toolStatusTone } from "../lib/format";

type Tab = "overview" | "findings" | "inventory" | "components" | "log";

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
      label: "Isolated extraction & built-in scan",
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
    ["osv", "Vulnerability DB"],
    ["fwanalyzer", "FwAnalyzer"],
    ["cwe_checker", "cwe_checker"],
    ["ghidra", "Ghidra"],
    ["fact", "FACT"],
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

export default function ScanDetail() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [artifacts, setArtifacts] = useState<Awaited<ReturnType<typeof api.artifacts>> | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
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

  async function act(kind: ExportKind | "rescan" | "delete") {
    setBusy(kind);
    try {
      if (kind in EXPORTS) await api.download(id, kind as ExportKind);
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
        {!error && <div className="empty">Loading scan…</div>}
      </div>
    );
  }

  const ident = scan.identification;
  const steps = pipelineSteps(scan);
  return (
    <div className="page">
      <header className="page-head">
        <div className="title-block">
          <div className="crumbs">
            <Link to="/scans">Scan history</Link> / <span className="mono">{scan.id.slice(0, 8)}</span>
          </div>
          <h1 className="break">{scan.original_filename}</h1>
          <div className="head-meta">
            <StatusBadge status={scan.status} />
            <span className="muted">{formatBytes(scan.size)}</span>
            <CopyText text={scan.sha256} display={`sha256 ${scan.sha256.slice(0, 20)}…`} />
            <span className="muted small">uploaded {formatDate(scan.created_at)}</span>
            {scan.finished_at && <span className="muted small">took {formatDuration(scan.started_at, scan.finished_at)}</span>}
          </div>
        </div>
        <div className="head-actions">
          <button className="btn" disabled={scan.status !== "completed" || !!busy} onClick={() => act("pdf")}>
            {busy === "pdf" ? "Generating…" : "Export PDF"}
          </button>
          <button className="btn ghost" disabled={!!busy || running} onClick={() => act("json")}>
            JSON
          </button>
          <button className="btn ghost" disabled={scan.status !== "completed" || !!busy} onClick={() => act("sarif")} title="SARIF 2.1.0 for code-scanning tools">
            SARIF
          </button>
          <button className="btn ghost" disabled={scan.status !== "completed" || !!busy} onClick={() => act("sbom")} title="CycloneDX 1.5 software bill of materials">
            SBOM
          </button>
          {scan.can_modify !== false && (
            <>
              <button className="btn ghost" disabled={running || !!busy} onClick={() => act("rescan")}>
                Re-scan
              </button>
              <button className="btn danger ghost" disabled={scan.status === "running" || !!busy} onClick={() => act("delete")}>
                Delete
              </button>
            </>
          )}
        </div>
      </header>
      <ErrorBox error={error} />

      <Panel className="pipeline-panel">
        <ol className="pipeline" aria-label="Scan pipeline">
          {steps.map((s) => (
            <li key={s.key} className={`step ${s.state}`} title={s.note}>
              <span className="step-dot" />
              <span className="step-label">{s.label}</span>
              <span className="step-state">{s.note === "timeout" ? "timeout" : s.state}</span>
            </li>
          ))}
        </ol>
        {running && (
          <div className="live">
            <div className="progress">
              <span style={{ width: `${Math.max(scan.progress, 3)}%` }} />
            </div>
            <div className="mono small muted">
              {scan.progress}% · {scan.stage} · {scan.events?.length ? scan.events[scan.events.length - 1].message : "waiting for worker"}
            </div>
          </div>
        )}
        {scan.status === "failed" && <div className="error-box">Scan failed: {scan.error}</div>}
      </Panel>

      <div className="tabs" role="tablist">
        {(
          [
            ["overview", "Overview"],
            ["findings", `Findings${findings ? ` (${findings.length})` : ""}`],
            ["inventory", `Inventory${artifacts ? ` (${artifacts.total})` : ""}`],
            ["components", `Components & packages (${(scan.components?.length ?? 0) + (scan.packages?.count ?? 0)})`],
            ["log", "Activity log"],
          ] as [Tab, string][]
        ).map(([k, label]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>
            {label}
          </button>
        ))}
      </div>

      {tab === "overview" && <Overview scan={scan} />}
      {tab === "findings" &&
        (findings ? <Panel><FindingsTable findings={findings} /></Panel> : <Empty>{running ? "Findings appear when the scan completes." : "Loading…"}</Empty>)}
      {tab === "inventory" && <Inventory data={artifacts} running={running} />}
      {tab === "components" && <Components scan={scan} />}
      {tab === "log" && <ActivityLog scan={scan} />}
      {!ident && !running && scan.status !== "failed" && <Empty>No identification data.</Empty>}
    </div>
  );
}

function Overview({ scan }: { scan: Scan }) {
  const ident = scan.identification;
  const cls = scan.classification_counts;
  const ex = scan.extraction_summary;
  return (
    <div className="grid-3">
      <Panel title="Firmware identification" className="span-2">
        {ident ? (
          <div className="ident">
            <div className="ident-hero">
              <div className="platform">
                {Icon.chip}
                <span className="platform-name">{ident.platform}</span>
                {ident.platform_confidence && <span className={`pill conf-${ident.platform_confidence}`}>{ident.platform_confidence} confidence</span>}
              </div>
              <div className="muted small">{ident.platform_family}</div>
            </div>
            <dl className="kv two-col">
              <dt>Format</dt>
              <dd>{ident.format_description}</dd>
              <dt>Architecture</dt>
              <dd>
                {ident.architecture ?? "unknown"}
                {ident.bits ? ` · ${ident.bits}-bit` : ""}
                {ident.endianness ? ` · ${ident.endianness}-endian` : ""}
              </dd>
              <dt>OS / runtime</dt>
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
                    {ident.board_hint ? ` — ${ident.board_hint}` : ""}
                  </dd>
                </>
              )}
              {ident.board_name && (
                <>
                  <dt>Board / target</dt>
                  <dd className="mono">{shown(ident.board_name)}</dd>
                </>
              )}
              {buildLine(ident.build) && (
                <>
                  <dt>Build</dt>
                  <dd className="mono small">{buildLine(ident.build)}</dd>
                </>
              )}
              <dt>Entropy</dt>
              <dd>{ident.entropy.toFixed(2)} bits/byte</dd>
              <dt>Isolation</dt>
              <dd className="small">{ex?.isolation_detail ?? scan.isolation ?? "–"}</dd>
            </dl>
            {ident.platform_candidates.length > 0 && (
              <details className="candidates">
                <summary>Platform evidence ({ident.platform_candidates.length} candidate(s))</summary>
                <ul>
                  {ident.platform_candidates.map((c) => (
                    <li key={c.name}>
                      <b>{c.name}</b> <span className="muted">score {c.score}, {c.confidence}</span>
                      <div className="mono small muted">{shown(c.evidence.join(" · "))}</div>
                    </li>
                  ))}
                </ul>
              </details>
            )}
            {ident.ardupilot_descriptor && (
              <details className="candidates">
                <summary>ArduPilot app descriptor</summary>
                <dl className="kv two-col mono small">
                  {Object.entries(ident.ardupilot_descriptor).map(([k, v]) => (
                    <div key={k} className="kv-row">
                      <dt>{k}</dt>
                      <dd>{String(v)}</dd>
                    </div>
                  ))}
                </dl>
              </details>
            )}
            {Object.keys(ident.container_metadata ?? {}).length > 0 && (
              <details className="candidates">
                <summary>Container metadata</summary>
                <dl className="kv two-col mono small">
                  {Object.entries(ident.container_metadata).map(([k, v]) => (
                    <div key={k} className="kv-row">
                      <dt>{k}</dt>
                      <dd>{String(v)}</dd>
                    </div>
                  ))}
                </dl>
              </details>
            )}
          </div>
        ) : (
          <Empty>Identification is available once isolated analysis finishes.</Empty>
        )}
      </Panel>
      <Panel title="Risk">
        <RiskGauge score={scan.risk_score} />
        <p className="muted small center">Heuristic summary of severity × evidence class. Not a probability of compromise.</p>
      </Panel>
      <Panel title="Severity breakdown">
        <SeverityDonut counts={scan.severity_counts ?? {}} />
      </Panel>
      <Panel title="Evidence class">
        <StackedBar
          items={[
            { key: "detected", label: "detected", value: cls?.detected ?? 0, color: "var(--cls-detected)" },
            { key: "suspicious", label: "suspicious", value: cls?.suspicious ?? 0, color: "var(--cls-suspicious)" },
            { key: "unverified", label: "unverified", value: cls?.unverified ?? 0, color: "var(--cls-unverified)" },
            { key: "info", label: "info", value: cls?.info ?? 0, color: "var(--cls-info)" },
          ]}
        />
        <ul className="cls-help small muted">
          <li>
            <b>detected</b> — concrete evidence present; exploitability not verified
          </li>
          <li>
            <b>suspicious</b> — heuristic match, may be a false positive
          </li>
          <li>
            <b>unverified</b> — version-based or static-analysis warning
          </li>
        </ul>
      </Panel>
      <Panel title="Extraction">
        {ex ? (
          <>
            <div className="stats compact">
              <div>
                <b>{ex.artifact_count}</b>
                <span className="muted small">artifacts</span>
              </div>
              <div>
                <b>{ex.filesystems.length}</b>
                <span className="muted small">containers / FS</span>
              </div>
              <div>
                <b>{ex.link_count}</b>
                <span className="muted small">links (not followed)</span>
              </div>
            </div>
            <div className="tags">
              {Object.entries(ex.categories).map(([k, v]) => (
                <span className="tag" key={k}>
                  {k.replace("_", " ")} <b>{v}</b>
                </span>
              ))}
            </div>
            {ex.limits_hit.length > 0 && <div className="warn-box small">Limits reached: {ex.limits_hit.join("; ")}</div>}
            {ex.warnings.length > 0 && (
              <details>
                <summary className="small">{ex.warnings.length} extraction warning(s)</summary>
                <ul className="mono small warn-list">
                  {ex.warnings.map((w, i) => (
                    <li key={i}>{shown(w)}</li>
                  ))}
                </ul>
              </details>
            )}
          </>
        ) : (
          <Empty>Pending.</Empty>
        )}
      </Panel>
      <Panel title="Analysis engines" className="span-3">
        <ToolRuns runs={scan.tool_runs ?? []} />
      </Panel>
    </div>
  );
}

function ToolRuns({ runs }: { runs: ToolRun[] }) {
  if (!runs.length) return <Empty>No tool has reported yet.</Empty>;
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Engine</th>
          <th>Status</th>
          <th>Findings</th>
          <th>Duration</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {runs.map((r, i) => (
          <tr key={i}>
            <td className="strong">{r.display_name}</td>
            <td>
              <span className={`pill ${toolStatusTone(r.status)}`}>{r.status}</span>
            </td>
            <td>{r.findings_count}</td>
            <td className="mono small">{r.duration_s !== null ? `${r.duration_s.toFixed(1)}s` : "–"}</td>
            <td className="small tool-msg">{r.message}</td>
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
  if (!data) return <Empty>{running ? "Inventory appears when extraction completes." : "Loading…"}</Empty>;
  const items = data.items.filter((a: Artifact) => (!cat || a.category === cat) && (!q || a.display_path.toLowerCase().includes(q.toLowerCase())));
  return (
    <Panel>
      <div className="filter-row">
        <select value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Filter by category">
          <option value="">All categories</option>
          {cats.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <input type="search" placeholder="Filter path…" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="muted small">{inventoryCount(items.length, data.items.length, data.total)}</span>
      </div>
      <div className="table-scroll">
        <table className="table inventory">
          <thead>
            <tr>
              <th>Path</th>
              <th>Category</th>
              <th>Format</th>
              <th>Size</th>
              <th>Arch / hardening</th>
              <th>Mode</th>
            </tr>
          </thead>
          <tbody>
            {items.slice(0, INVENTORY_ROWS).map((a) => {
              const elf = a.elf as Record<string, string | boolean | null> | undefined;
              return (
                <tr key={a.id}>
                  <td className="mono small path" style={{ paddingLeft: `${8 + a.depth * 12}px` }} title={shown(a.display_path)}>
                    {shown(a.name)}
                    {a.extraction && a.extraction !== "ok" && <span className={`pill ${a.extraction === "failed" ? "bad" : "warn"}`}>{a.extraction}</span>}
                  </td>
                  <td>
                    <span className="tag">{a.category}</span>
                  </td>
                  <td className="small">{a.format_description}</td>
                  <td className="mono small">{formatBytes(a.size)}</td>
                  <td className="small">
                    {elf ? (
                      <>
                        {String(elf.arch)}
                        {elf.os_hint === "linux" && elf.interpreter ? (
                          <span className="hardening">
                            <span className={elf.nx ? "ok" : "bad"}>NX</span>
                            <span className={elf.pie ? "ok" : "bad"}>PIE</span>
                            <span className={elf.relro === "full" ? "ok" : elf.relro === "partial" ? "warn" : "bad"}>RELRO</span>
                            <span className={elf.canary ? "ok" : "bad"}>Canary</span>
                          </span>
                        ) : null}
                      </>
                    ) : imageSummary(a.image) ? (
                      <span className="mono small">{imageSummary(a.image)}</span>
                    ) : (
                      "–"
                    )}
                  </td>
                  <td className="mono small">{a.mode !== null && a.mode !== undefined ? a.mode.toString(8).padStart(4, "0") : "–"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {data.link_count > 0 && (
        <details>
          <summary className="small">
            {data.link_count} symlink/hardlink/device entries recorded but not materialised (traversal protection)
          </summary>
          <ul className="mono small warn-list">
            {data.links.slice(0, 200).map((l, i) => (
              <li key={i}>
                [{l.kind}] {shown(l.path)}
                {l.target ? ` → ${shown(l.target)}` : ""}
              </li>
            ))}
          </ul>
        </details>
      )}
    </Panel>
  );
}

const SEV_ORDER = ["critical", "high", "medium", "low"];

function worst(v: VulnRef[] | undefined): string | null {
  const sevs = (v ?? []).map((x) => x.severity ?? "medium");
  return SEV_ORDER.find((s) => sevs.includes(s)) ?? (sevs.length ? "medium" : null);
}

function VulnList({ vulns }: { vulns: VulnRef[] }) {
  return (
    <details>
      <summary className="small">
        <span className={`pill sev-${worst(vulns)}`}>{vulns.length}</span> {vulns.slice(0, 3).map((v) => v.id).join(", ")}
        {vulns.length > 3 ? "…" : ""}
      </summary>
      <table className="table compact">
        <tbody>
          {vulns.slice(0, 200).map((v) => (
            <tr key={v.id}>
              <td className="mono small">
                <a href={`https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`} target="_blank" rel="noreferrer noopener">
                  {v.id}
                </a>
              </td>
              <td className="small">
                {v.severity ?? "n/a"}
                {v.score ? ` (${v.score})` : ""}
              </td>
              <td className="small mono">{v.fixed ? `fixed in ${v.fixed}` : "no fix listed"}</td>
              <td className="small muted mono">{v.aliases.slice(0, 2).join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}

function Components({ scan }: { scan: Scan }) {
  const comps = scan.components ?? [];
  const [inv, setInv] = useState<PackageInventory | null>(null);
  const [onlyVuln, setOnlyVuln] = useState(false);
  const [q, setQ] = useState("");
  const [err, setErr] = useState<unknown>(null);
  useEffect(() => {
    if (scan.packages?.count) api.packages(scan.id).then(setInv).catch(setErr);
  }, [scan.id, scan.packages?.count]);
  const pk = (inv?.items ?? []).filter(
    (p: PackageItem) => (!onlyVuln || (p.vulnerabilities?.length ?? 0) > 0) && (!q || `${p.name} ${p.source ?? ""}`.toLowerCase().includes(q.toLowerCase())),
  );
  return (
    <div className="stack">
      {scan.packages?.count ? (
        <Panel
          title="Installed packages"
          actions={
            <span className="muted small">
              From the package manager database{scan.packages.distro ? ` · ${scan.packages.distro.name || `${scan.packages.distro.id} ${scan.packages.distro.version_id}`}` : ""} ·{" "}
              {scan.packages.vulnerable} with known vulnerabilities (OSV, backport-aware)
            </span>
          }
        >
          <ErrorBox error={err} />
          <div className="filter-row">
            <label className="small">
              <input type="checkbox" checked={onlyVuln} onChange={(e) => setOnlyVuln(e.target.checked)} /> only packages with known vulnerabilities
            </label>
            <input type="search" placeholder="Filter package…" value={q} onChange={(e) => setQ(e.target.value)} />
            <span className="muted small">
              {pk.length} / {inv?.total ?? scan.packages.count}
            </span>
          </div>
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Version</th>
                  <th>Source package</th>
                  <th>Files</th>
                  <th>Known vulnerabilities</th>
                </tr>
              </thead>
              <tbody>
                {pk.slice(0, 2000).map((p) => (
                  <tr key={`${p.manager}-${p.name}-${p.version}`}>
                    <td className="strong">
                      {shown(p.name)} <span className="tag">{p.manager}</span>
                    </td>
                    <td className="mono small">{shown(p.version)}</td>
                    <td className="mono small muted">{p.source && p.source !== p.name ? shown(`${p.source} ${p.source_version ?? ""}`) : "–"}</td>
                    <td className="small" title={p.owned_files == null ? "file ownership was not recorded for this scan" : undefined}>
                      {p.owned_files ?? "–"}
                    </td>
                    <td>{p.vulnerabilities?.length ? <VulnList vulns={p.vulnerabilities} /> : <span className="muted small">none listed</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : null}
      <Panel title="Software components" actions={<span className="muted small">Identified from version strings and descriptors — verify before relying on them.</span>}>
        {comps.length === 0 ? (
          <Empty>No software components with recognisable version strings were found.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Component</th>
                <th>Version</th>
                <th>Method</th>
                <th>Found in</th>
                <th>Known vulnerabilities (version match)</th>
              </tr>
            </thead>
            <tbody>
              {comps.map((c) => (
                <tr key={`${c.name}-${c.version}`}>
                  <td className="strong">
                    {shown(c.name)}
                    {c.variant ? <span className="tag">{c.variant}</span> : null}
                  </td>
                  <td className="mono">{shown(c.version)}</td>
                  <td className="small muted">{c.method}</td>
                  <td className="mono small">{shown(c.sources.join(" · "))}</td>
                  <td>
                    {c.vulnerabilities?.length ? (
                      <VulnList vulns={c.vulnerabilities} />
                    ) : (
                      <span className="muted small">{c.vulnerabilities_note ?? (c.vulnerabilities ? "none listed" : "not checked")}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

function ActivityLog({ scan }: { scan: Scan }) {
  const ev = scan.events ?? [];
  return (
    <Panel title="Activity log">
      {ev.length === 0 ? (
        <Empty>No events yet.</Empty>
      ) : (
        <ol className="log">
          {ev.map((e, i) => (
            <li key={i} className={`lvl-${e.level}`}>
              <span className="mono small muted">{new Date(e.ts).toLocaleTimeString()}</span>
              <span className="tag">{e.stage}</span>
              <span>{e.message}</span>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}
