import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Empty, ErrorBox, SeverityCounts, StatusBadge, usePolling } from "../components/ui";
import { api, Scan } from "../lib/api";
import { formatBytes, formatDate, shortHash } from "../lib/format";

const PAGE = 25;

export default function History() {
  const [items, setItems] = useState<Scan[]>([]);
  const [total, setTotal] = useState(0);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [error, setError] = useState<unknown>(null);
  const [selected, setSelected] = useState<Scan[]>([]);
  const navigate = useNavigate();

  function toggle(s: Scan) {
    setSelected((cur) => (cur.some((x) => x.id === s.id) ? cur.filter((x) => x.id !== s.id) : [...cur, s].slice(-2)));
  }
  function compareSelected() {
    const [a, b] = [...selected].sort((x, y) => x.created_at.localeCompare(y.created_at));
    navigate(`/compare?base=${a.id}&target=${b.id}`);
  }

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
          <h1>Scans</h1>
          <p className="lede">
            {total} {total === 1 ? "scan" : "scans"}. Select two completed scans to compare releases.
          </p>
        </div>
        <button className="btn primary" disabled={selected.length !== 2} onClick={compareSelected}>
          Compare selected ({selected.length} of 2)
        </button>
      </header>
      <ErrorBox error={error} />
      <div className="filters">
        <input
          type="search"
          placeholder="Search file name or SHA-256"
          aria-label="Search scans"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setPage(0);
          }}
        />
        <span className="filter">
          <label htmlFor="hist-status">Status</label>
          <select
            id="hist-status"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(0);
            }}
          >
            <option value="">Any</option>
            <option value="queued">Queued</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
          </select>
        </span>
      </div>
      {items.length === 0 ? (
        <Empty>No scans match.</Empty>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th aria-label="Select" />
              <th>Firmware</th>
              <th>SHA-256</th>
              <th>Platform</th>
              <th>Status</th>
              <th className="num">Risk</th>
              <th>Findings</th>
              <th>Uploaded</th>
            </tr>
          </thead>
          <tbody>
            {items.map((s) => (
              <tr key={s.id}>
                <td>
                  <input
                    type="checkbox"
                    aria-label={`Select ${s.original_filename} for comparison`}
                    disabled={s.status !== "completed"}
                    checked={selected.some((x) => x.id === s.id)}
                    onChange={() => toggle(s)}
                  />
                </td>
                <td>
                  <Link to={`/scans/${s.id}`}>{s.original_filename}</Link>
                  <div className="muted">{formatBytes(s.size)}</div>
                </td>
                <td className="mono muted">{shortHash(s.sha256, 12)}</td>
                <td>
                  {s.identification?.platform ?? <span className="muted">–</span>}
                  {s.identification?.architecture && <div className="muted">{s.identification.architecture}</div>}
                </td>
                <td>
                  <StatusBadge status={s.status} />
                </td>
                <td className="num">{s.risk_score ?? <span className="muted">–</span>}</td>
                <td>
                  <SeverityCounts counts={s.severity_counts} />
                </td>
                <td className="muted nowrap">{formatDate(s.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {total > PAGE && (
        <div className="pager">
          <button className="btn" disabled={page === 0} onClick={() => setPage(page - 1)}>
            Previous
          </button>
          <span className="muted">
            Page {page + 1} of {Math.ceil(total / PAGE)}
          </span>
          <button className="btn" disabled={(page + 1) * PAGE >= total} onClick={() => setPage(page + 1)}>
            Next
          </button>
        </div>
      )}
    </div>
  );
}
