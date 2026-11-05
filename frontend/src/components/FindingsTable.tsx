import { useMemo, useState } from "react";
import { CLASSIFICATIONS, Classification, Finding, SEVERITIES, Severity } from "../lib/api";
import { CLASSIFICATION_HELP, externalUrl, findingBasis, shown } from "../lib/format";
import { ClassBadge, Empty, SeverityBadge } from "./ui";

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [sev, setSev] = useState<Set<Severity>>(new Set());
  const [cls, setCls] = useState<Set<Classification>>(new Set());
  const [tool, setTool] = useState("");
  const [pkg, setPkg] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<number | null>(null);

  const tools = useMemo(() => Array.from(new Set(findings.map((f) => f.source_tool))).sort(), [findings]);
  const packages = useMemo(() => Array.from(new Set(findings.map((f) => f.package).filter((p): p is string => !!p))).sort(), [findings]);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return findings.filter(
      (f) =>
        (!sev.size || sev.has(f.severity)) &&
        (!cls.size || cls.has(f.classification)) &&
        (!tool || f.source_tool === tool) &&
        (!pkg || f.package === pkg) &&
        (!needle ||
          f.title.toLowerCase().includes(needle) ||
          f.affected_component.toLowerCase().includes(needle) ||
          (f.package ?? "").toLowerCase().includes(needle) ||
          (f.cwe ?? "").toLowerCase().includes(needle)),
    );
  }, [findings, sev, cls, tool, pkg, q]);

  function toggle<T>(set: Set<T>, v: T, update: (s: Set<T>) => void) {
    const n = new Set(set);
    if (n.has(v)) n.delete(v);
    else n.add(v);
    update(n);
  }

  const sevCount = (s: Severity) => findings.filter((f) => f.severity === s).length;
  const clsCount = (c: Classification) => findings.filter((f) => f.classification === c).length;

  return (
    <div className="findings">
      <div className="filters">
        <div className="chips" aria-label="Filter by severity">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              className={`chip sev-${s} ${sev.has(s) ? "on" : ""}`}
              onClick={() => toggle(sev, s, setSev)}
              aria-pressed={sev.has(s)}
            >
              {s} <b>{sevCount(s)}</b>
            </button>
          ))}
        </div>
        <div className="chips" aria-label="Filter by classification">
          {CLASSIFICATIONS.map((c) => (
            <button
              key={c}
              type="button"
              className={`chip cls-${c} ${cls.has(c) ? "on" : ""}`}
              onClick={() => toggle(cls, c, setCls)}
              title={CLASSIFICATION_HELP[c]}
              aria-pressed={cls.has(c)}
            >
              {c} <b>{clsCount(c)}</b>
            </button>
          ))}
        </div>
        <div className="filter-row">
          <select value={tool} onChange={(e) => setTool(e.target.value)} aria-label="Filter by tool">
            <option value="">All tools</option>
            {tools.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          {packages.length > 0 && (
            <select value={pkg} onChange={(e) => setPkg(e.target.value)} aria-label="Filter by package">
              <option value="">All packages</option>
              {packages.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          )}
          <input type="search" placeholder="Search title, component, package, CWE…" value={q} onChange={(e) => setQ(e.target.value)} />
          <span className="muted small">
            {filtered.length} / {findings.length}
          </span>
        </div>
      </div>

      {filtered.length === 0 ? (
        <Empty>{findings.length ? "No findings match the filters." : "No findings were produced. This does not mean the firmware is free of vulnerabilities."}</Empty>
      ) : (
        <ul className="finding-list">
          {filtered.map((f) => {
            const isOpen = open === f.id;
            return (
              <li key={f.id} className={`finding ${isOpen ? "open" : ""} edge-${f.severity}`}>
                <button type="button" className="finding-head" onClick={() => setOpen(isOpen ? null : f.id)} aria-expanded={isOpen}>
                  <SeverityBadge severity={f.severity} />
                  <ClassBadge value={f.classification} />
                  <span className="finding-title">{shown(f.title)}</span>
                  {f.tags
                    .filter((t) => t.startsWith("corroborated-by:"))
                    .map((t) => (
                      <span key={t} className="pill ok" title="The same issue was independently reported by this tool">
                        ✓ {t.replace("corroborated-by:", "")}
                      </span>
                    ))}
                  {f.package && (
                    <span className="pill pkg" title="Installed package that owns the affected file">
                      {shown(f.package)}
                    </span>
                  )}
                  <span className="finding-meta mono">{f.source_tool}</span>
                  <span className="chev">{isOpen ? "▾" : "▸"}</span>
                </button>
                <div className="finding-component mono" title={shown(f.affected_component)}>
                  {shown(f.affected_component)}
                </div>
                {isOpen && (
                  <div className="finding-body">
                    <p>{f.description}</p>
                    <dl className="kv">
                      <dt>Basis</dt>
                      <dd>
                        <b>{findingBasis(f).label}.</b> {findingBasis(f).text}
                      </dd>
                      {f.package && (
                        <>
                          <dt>Package</dt>
                          <dd className="mono">{shown(f.package)}</dd>
                        </>
                      )}
                      <dt>Classification</dt>
                      <dd>
                        {f.classification} — {CLASSIFICATION_HELP[f.classification]} Confidence: <b>{f.confidence}</b>.
                      </dd>
                      <dt>Rule</dt>
                      <dd className="mono">
                        {f.source_tool} / {f.rule_id}
                        {f.cwe && (
                          <>
                            {" · "}
                            <a href={`https://cwe.mitre.org/data/definitions/${f.cwe.replace("CWE-", "")}.html`} target="_blank" rel="noreferrer noopener">
                              {f.cwe}
                            </a>
                          </>
                        )}
                      </dd>
                      <dt>Remediation</dt>
                      <dd>{f.remediation}</dd>
                    </dl>
                    {f.evidence.length > 0 && (
                      <div className="evidence">
                        <div className="evidence-title">Evidence</div>
                        <table>
                          <tbody>
                            {f.evidence.map((e, i) => (
                              <tr key={i}>
                                <td className="ev-kind">{e.kind}</td>
                                <td className="mono ev-value">{shown(e.value)}</td>
                                <td className="mono ev-loc">{shown(e.location)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                    {f.references.length > 0 && (
                      <div className="refs">
                        {f.references.map((r) => {
                          const href = externalUrl(r);
                          return href ? (
                            <a key={r} href={href} target="_blank" rel="noreferrer noopener">
                              {r}
                            </a>
                          ) : (
                            <span key={r} className="tag">
                              {r}
                            </span>
                          );
                        })}
                      </div>
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
