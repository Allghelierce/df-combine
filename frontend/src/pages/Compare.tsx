import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { FindingsTable } from "../components/FindingsTable";
import { Empty, ErrorBox, Section, SeverityBadge } from "../components/ui";
import { api, Comparison } from "../lib/api";
import { capitalize, formatDate } from "../lib/format";

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

  if (!base || !target) return <div className="page"><Empty>Select two completed scans on the Scans page to compare them.</Empty></div>;
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
      <div className="crumbs">
        <Link to="/scans">Scans</Link> / compare
      </div>
      <h1>Compare releases</h1>
      <p className="lede">
        Findings are matched by tool, rule and path inside the filesystem, so renamed packages still line up. Version-based findings follow the
        component.
      </p>
      <dl className="kv">
        {(["base", "target"] as const).map((k) => (
          <div key={k} className="kv-row">
            <dt>{k === "base" ? "Older" : "Newer"}</dt>
            <dd>
              <Link to={`/scans/${data[k].id}`}>{data[k].original_filename}</Link>
              <span className="muted">
                {" "}
                {[data[k].identification?.platform, data[k].identification?.platform_version, `uploaded ${formatDate(data[k].created_at)}`, `risk ${data[k].risk_score ?? "–"}`]
                  .filter(Boolean)
                  .join(", ")}
              </span>
            </dd>
          </div>
        ))}
      </dl>
      <p className="summary">
        {s.new} new, {s.resolved} resolved, {s.severity_changed} changed severity, {s.component_changes} component changes
      </p>
      {data.components.length > 0 && (
        <Section title="Component changes">
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
                  <td>{c.name}</td>
                  <td>{capitalize(c.change)}</td>
                  <td className="mono">{c.before.join(", ") || "–"}</td>
                  <td className="mono">{c.after.join(", ") || "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}
      <div className="tabs" role="tablist">
        {tabs.map(([k, label, n]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>
            {label} ({n})
          </button>
        ))}
      </div>
      {tab === "severity_changed" && data.severity_changed.length > 0 && (
        <ul className="plain-list">
          {data.severity_changed.map((f) => (
            <li key={f.id}>
              <SeverityBadge severity={f.previous_severity} /> to <SeverityBadge severity={f.severity} />: {f.title}
            </li>
          ))}
        </ul>
      )}
      <FindingsTable findings={data[tab]} />
    </div>
  );
}
