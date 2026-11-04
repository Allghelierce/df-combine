import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { FindingsTable } from "../components/FindingsTable";
import { Empty, ErrorBox, Panel, SeverityBadge } from "../components/ui";
import { api, Comparison } from "../lib/api";
import { formatDate } from "../lib/format";

type Tab = "new" | "resolved" | "severity_changed" | "unchanged";

export default function Compare() {
  const [params] = useSearchParams();
  const base = params.get("base") ?? "";
  const target = params.get("target") ?? "";
  const [data, setData] = useState<Comparison | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [tab, setTab] = useState<Tab>("new");

  useEffect(() => {
    if (!base || !target) return;
    api.compare(base, target).then(setData).catch(setError);
  }, [base, target]);

  if (!base || !target) return <Empty>Select two completed scans in the scan history to compare them.</Empty>;
  if (!data)
    return (
      <div className="page">
        <ErrorBox error={error} />
        {!error && <Empty>Comparing…</Empty>}
      </div>
    );

  const s = data.summary;
  const tabs: [Tab, string, number][] = [
    ["new", "New", s.new],
    ["resolved", "Resolved", s.resolved],
    ["severity_changed", "Severity changed", s.severity_changed],
    ["unchanged", "Unchanged", s.unchanged],
  ];
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <div className="crumbs">
            <Link to="/scans">Scan history</Link> / compare
          </div>
          <h1>Release comparison</h1>
          <p className="muted">
            Findings are matched by tool, rule and in-filesystem path, so renamed packages still line up. Version-based findings
            follow the component.
          </p>
        </div>
      </header>
      <div className="grid-2">
        {(["base", "target"] as const).map((k) => (
          <Panel key={k} title={k === "base" ? "Baseline (older)" : "Target (newer)"}>
            <Link to={`/scans/${data[k].id}`} className="strong">
              {data[k].original_filename}
            </Link>
            <div className="muted small">
              {data[k].identification?.platform} · {data[k].identification?.platform_version ?? "version n/a"} · uploaded{" "}
              {formatDate(data[k].created_at)} · risk {data[k].risk_score ?? "–"}
            </div>
          </Panel>
        ))}
      </div>
      <div className="stats">
        <div className="stat tone-critical">
          <div className="stat-label">New findings</div>
          <div className="stat-value">{s.new}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Resolved</div>
          <div className="stat-value" style={{ color: "var(--ok)" }}>
            {s.resolved}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Severity changed</div>
          <div className="stat-value">{s.severity_changed}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Component changes</div>
          <div className="stat-value">{s.component_changes}</div>
        </div>
      </div>
      {data.components.length > 0 && (
        <Panel title="Component changes">
          <table className="table">
            <thead>
              <tr>
                <th>Component</th>
                <th>Change</th>
                <th>Before</th>
                <th>After</th>
              </tr>
            </thead>
            <tbody>
              {data.components.map((c) => (
                <tr key={c.name}>
                  <td className="strong">{c.name}</td>
                  <td>
                    <span className={`pill ${c.change === "removed" ? "muted" : c.change === "added" ? "warn" : "ok"}`}>{c.change}</span>
                  </td>
                  <td className="mono">{c.before.join(", ") || "–"}</td>
                  <td className="mono">{c.after.join(", ") || "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
      <div className="tabs" role="tablist">
        {tabs.map(([k, label, n]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>
            {label} ({n})
          </button>
        ))}
      </div>
      {tab === "severity_changed" && data.severity_changed.length > 0 && (
        <Panel>
          <ul className="tool-mini">
            {data.severity_changed.map((f) => (
              <li key={f.id}>
                <SeverityBadge severity={f.previous_severity} /> → <SeverityBadge severity={f.severity} /> <span>{f.title}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
      <Panel>
        <FindingsTable findings={data[tab]} />
      </Panel>
    </div>
  );
}
