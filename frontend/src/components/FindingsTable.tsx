import { useId, useMemo, useState } from "react";
import { CLASSIFICATIONS, Classification, Finding, SEVERITIES, Severity } from "../lib/api";
import { capitalize, CLASSIFICATION_HELP } from "../lib/format";
import { Empty, SeverityBadge } from "./ui";

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [sev, setSev] = useState<Severity | "">("");
  const [cls, setCls] = useState<Classification | "">("");
  const [tool, setTool] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const id = useId();

  const tools = useMemo(() => Array.from(new Set(findings.map((f) => f.source_tool))).sort(), [findings]);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return findings.filter(
      (f) =>
        (!sev || f.severity === sev) &&
        (!cls || f.classification === cls) &&
        (!tool || f.source_tool === tool) &&
        (!needle ||
          f.title.toLowerCase().includes(needle) ||
          f.affected_component.toLowerCase().includes(needle) ||
          (f.cwe ?? "").toLowerCase().includes(needle)),
    );
  }, [findings, sev, cls, tool, q]);

  const sevCount = (s: Severity) => findings.filter((f) => f.severity === s).length;
  const clsCount = (c: Classification) => findings.filter((f) => f.classification === c).length;

  return (
    <div className="findings">
      <div className="filters">
        <span className="filter">
          <label htmlFor={`${id}-sev`}>Severity</label>
          <select id={`${id}-sev`} value={sev} onChange={(e) => setSev(e.target.value as Severity | "")}>
            <option value="">All</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {capitalize(s)} ({sevCount(s)})
              </option>
            ))}
          </select>
        </span>
        <span className="filter">
          <label htmlFor={`${id}-cls`}>Evidence</label>
          <select id={`${id}-cls`} value={cls} onChange={(e) => setCls(e.target.value as Classification | "")}>
            <option value="">All</option>
            {CLASSIFICATIONS.map((c) => (
              <option key={c} value={c} title={CLASSIFICATION_HELP[c]}>
                {capitalize(c)} ({clsCount(c)})
              </option>
            ))}
          </select>
        </span>
        <span className="filter">
          <label htmlFor={`${id}-tool`}>Tool</label>
          <select id={`${id}-tool`} value={tool} onChange={(e) => setTool(e.target.value)}>
            <option value="">All</option>
            {tools.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </span>
        <input type="search" placeholder="Search title, path or CWE" aria-label="Search findings" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="muted count">
          {filtered.length} of {findings.length}
        </span>
      </div>

      {filtered.length === 0 ? (
        <Empty>{findings.length ? "No findings match these filters." : "No findings were produced. This does not mean the firmware is free of vulnerabilities."}</Empty>
      ) : (
        <ul className="finding-list">
          {filtered.map((f) => {
            const isOpen = open === f.id;
            const alsoBy = f.tags.filter((t) => t.startsWith("corroborated-by:")).map((t) => t.replace("corroborated-by:", ""));
            return (
              <li key={f.id} className={`finding ${isOpen ? "open" : ""}`}>
                <button type="button" className="finding-head" onClick={() => setOpen(isOpen ? null : f.id)} aria-expanded={isOpen}>
                  <SeverityBadge severity={f.severity} />
                  <span className="finding-main">
                    <span className="finding-title">{f.title}</span>
                    <span className="finding-path mono" title={f.affected_component}>
                      {f.affected_component}
                    </span>
                  </span>
                  <span className="finding-source">
                    <span>{capitalize(f.classification)}</span>
                    <span className="mono">{f.source_tool}</span>
                  </span>
                </button>
                {isOpen && (
                  <div className="finding-body">
                    <p>{f.description}</p>
                    <dl className="kv">
                      <dt>Evidence</dt>
                      <dd>
                        {capitalize(f.classification)}. {CLASSIFICATION_HELP[f.classification]} Confidence: {f.confidence}.
                      </dd>
                      <dt>Rule</dt>
                      <dd>
                        <span className="mono">
                          {f.source_tool} / {f.rule_id}
                        </span>
                        {f.cwe && (
                          <>
                            {", "}
                            <a href={`https://cwe.mitre.org/data/definitions/${f.cwe.replace("CWE-", "")}.html`} target="_blank" rel="noreferrer noopener">
                              {f.cwe}
                            </a>
                          </>
                        )}
                      </dd>
                      <dt>Fix</dt>
                      <dd>{f.remediation}</dd>
                    </dl>
                    {alsoBy.length > 0 && <p className="muted">{`Also reported by ${alsoBy.join(", ")}`}</p>}
                    {f.evidence.length > 0 && (
                      <table className="evidence">
                        <caption>Evidence</caption>
                        <tbody>
                          {f.evidence.map((e, i) => (
                            <tr key={i}>
                              <td className="muted">{e.kind}</td>
                              <td className="mono">{e.value}</td>
                              <td className="mono muted">{e.location}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                    {f.references.length > 0 && (
                      <ul className="refs">
                        {f.references.map((r) => (
                          <li key={r}>
                            {r.startsWith("http") ? (
                              <a href={r} target="_blank" rel="noreferrer noopener">
                                {r}
                              </a>
                            ) : (
                              r
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
