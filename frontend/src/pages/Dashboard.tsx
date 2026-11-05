import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { MiniSeverity, StackedBar } from "../components/charts";
import { Dropzone } from "../components/Dropzone";
import { Empty, ErrorBox, Panel, Stat, StatusBadge, usePolling } from "../components/ui";
import { api, AppConfig, Scan, Stats, ToolStatus } from "../lib/api";
import { formatBytes, formatDate } from "../lib/format";

export default function Dashboard({ config, canUpload = true }: { config: AppConfig | null; canUpload?: boolean }) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [recent, setRecent] = useState<Scan[]>([]);
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(() => {
    Promise.all([api.stats(), api.scans({ limit: 8 })])
      .then(([s, r]) => {
        setStats(s);
        setRecent(r.items);
        setError(null);
      })
      .catch(setError);
  }, []);

  useEffect(() => {
    load();
    api.tools().then((t) => setTools(t.tools)).catch(() => undefined);
  }, [load]);
  const active = recent.some((s) => s.status === "queued" || s.status === "running");
  usePolling(load, 3000, active);

  const sev = stats?.findings_by_severity ?? {};
  const cls = stats?.findings_by_classification ?? {};
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Firmware security dashboard</h1>
          <p className="muted">Upload PX4, ArduPilot, ESP32 peripheral or companion-computer firmware for automated static security analysis.</p>
        </div>
      </header>
      <ErrorBox error={error} />
      <div className="grid-2">
        <Panel title="New scan">
          {canUpload ? (
            <Dropzone maxMb={config?.max_upload_mb} onUploaded={load} />
          ) : (
            <Empty>Your role is read-only; ask an administrator for analyst access to upload firmware.</Empty>
          )}
        </Panel>
        <Panel title="Overview">
          <div className="stats">
            <Stat label="Scans" value={stats?.total_scans ?? "–"} sub={`${stats?.scans.completed ?? 0} completed`} />
            <Stat label="Running / queued" value={(stats?.scans.running ?? 0) + (stats?.scans.queued ?? 0)} tone={active ? "accent" : undefined} />
            <Stat label="Critical findings" value={sev.critical ?? 0} tone="critical" />
            <Stat label="High findings" value={sev.high ?? 0} tone="high" />
          </div>
          <div className="subhead">Evidence class across all scans</div>
          <StackedBar
            items={[
              { key: "detected", label: "detected", value: cls.detected ?? 0, color: "var(--cls-detected)" },
              { key: "suspicious", label: "suspicious", value: cls.suspicious ?? 0, color: "var(--cls-suspicious)" },
              { key: "unverified", label: "unverified", value: cls.unverified ?? 0, color: "var(--cls-unverified)" },
              { key: "info", label: "info", value: cls.info ?? 0, color: "var(--cls-info)" },
            ]}
          />
          {stats && Object.keys(stats.platforms).length > 0 && (
            <>
              <div className="subhead">Platforms identified</div>
              <div className="tags">
                {Object.entries(stats.platforms).map(([p, n]) => (
                  <span key={p} className="tag">
                    {p} <b>{n}</b>
                  </span>
                ))}
              </div>
            </>
          )}
        </Panel>
      </div>

      <div className="grid-2 wide-left">
        <Panel title="Recent scans" actions={<Link to="/scans" className="btn ghost sm">View all</Link>}>
          {recent.length === 0 ? (
            <Empty>No scans yet. Upload a firmware image to begin. Synthetic samples can be generated with <code>make fixtures</code>.</Empty>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Firmware</th>
                  <th>Platform</th>
                  <th>Status</th>
                  <th>Findings (C/H/M/L)</th>
                  <th>Uploaded</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <Link to={`/scans/${s.id}`} className="strong">
                        {s.original_filename}
                      </Link>
                      <div className="muted small mono">{formatBytes(s.size)}</div>
                    </td>
                    <td>{s.identification?.platform ?? <span className="muted">–</span>}</td>
                    <td>
                      <StatusBadge status={s.status} />
                      {s.status === "running" && <span className="muted small"> {s.progress}%</span>}
                    </td>
                    <td>
                      <MiniSeverity counts={s.severity_counts} />
                    </td>
                    <td className="muted small">{formatDate(s.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
        <Panel title="Analysis engines" actions={<Link to="/tools" className="btn ghost sm">Details</Link>}>
          <ul className="tool-mini">
            {tools.map((t) => (
              <li key={t.name}>
                <span className={`dot ${t.available ? "ok" : t.enabled ? "warn" : "muted"}`} />
                <span className="strong">{t.display_name}</span>
                <span className="muted small">{t.available ? t.mode ?? "available" : t.enabled ? "unavailable" : "not configured"}</span>
              </li>
            ))}
          </ul>
          <p className="muted small">
            Each scan reports which engines ran, were skipped as not applicable, or were unavailable. Missing engines are never silently ignored.
          </p>
        </Panel>
      </div>
    </div>
  );
}
