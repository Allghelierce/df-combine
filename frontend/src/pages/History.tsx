import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { MiniSeverity } from "../components/charts";
import { Empty, ErrorBox, Panel, StatusBadge, usePolling } from "../components/ui";
import { api, Scan } from "../lib/api";
import { formatBytes, formatDate, riskLabel, shortHash } from "../lib/format";

const PAGE = 25;

export default function History() {
  const [items, setItems] = useState<Scan[]>([]);
  const [total, setTotal] = useState(0);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(() => {
    api
      .scans({ q, status, limit: PAGE, offset: page * PAGE })
      .then((r) => {
        setItems(r.items);
        setTotal(r.total);
        setError(null);
      })
      .catch(setError);
  }, [q, status, page]);

  useEffect(() => {
    const t = setTimeout(load, 200);
    return () => clearTimeout(t);
  }, [load]);
  usePolling(load, 4000, items.some((s) => s.status === "running" || s.status === "queued"));

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Scan history</h1>
          <p className="muted">{total} scan(s). Search by file name or SHA-256.</p>
        </div>
      </header>
      <ErrorBox error={error} />
      <Panel>
        <div className="filter-row">
          <input
            type="search"
            placeholder="Search file name or hash…"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setPage(0);
            }}
          />
          <select
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(0);
            }}
            aria-label="Filter by status"
          >
            <option value="">Any status</option>
            <option value="queued">queued</option>
            <option value="running">running</option>
            <option value="completed">completed</option>
            <option value="failed">failed</option>
          </select>
        </div>
        {items.length === 0 ? (
          <Empty>No scans match.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Firmware</th>
                <th>SHA-256</th>
                <th>Platform / arch</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Findings (C/H/M/L)</th>
                <th>Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => {
                const r = riskLabel(s.risk_score);
                return (
                  <tr key={s.id}>
                    <td>
                      <Link to={`/scans/${s.id}`} className="strong">
                        {s.original_filename}
                      </Link>
                      <div className="muted small">{formatBytes(s.size)}</div>
                    </td>
                    <td className="mono small">{shortHash(s.sha256, 16)}</td>
                    <td>
                      {s.identification?.platform ?? "–"}
                      <div className="muted small">{s.identification?.architecture ?? ""}</div>
                    </td>
                    <td>
                      <StatusBadge status={s.status} />
                    </td>
                    <td>{s.risk_score !== null ? <span className={`risk tone-${r.tone}`}>{s.risk_score}</span> : <span className="muted">–</span>}</td>
                    <td>
                      <MiniSeverity counts={s.severity_counts} />
                    </td>
                    <td className="muted small">{formatDate(s.created_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {total > PAGE && (
          <div className="pager">
            <button className="btn ghost sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
              ← Prev
            </button>
            <span className="muted small">
              Page {page + 1} of {Math.ceil(total / PAGE)}
            </span>
            <button className="btn ghost sm" disabled={(page + 1) * PAGE >= total} onClick={() => setPage(page + 1)}>
              Next →
            </button>
          </div>
        )}
      </Panel>
    </div>
  );
}
