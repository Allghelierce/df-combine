import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Dropzone } from "../components/Dropzone";
import { Empty, ErrorBox, Section, SeverityCounts, StatusBadge, usePolling } from "../components/ui";
import { api, AppConfig, Scan } from "../lib/api";
import { formatBytes, formatDate } from "../lib/format";

export default function Dashboard({ config }: { config: AppConfig | null }) {
  const [recent, setRecent] = useState<Scan[]>([]);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(() => {
    api
      .scans({ limit: 8 })
      .then((r) => {
        setRecent(r.items);
        setError(null);
      })
      .catch(setError);
  }, []);

  useEffect(load, [load]);
  usePolling(load, 3000, recent.some((s) => s.status === "queued" || s.status === "running"));

  return (
    <div className="page">
      <h1>Upload firmware</h1>
      <p className="lede">PX4, ArduPilot and companion-computer images. Analysis is static; firmware is never executed.</p>
      <ErrorBox error={error} />
      <Dropzone maxMb={config?.max_upload_mb} onUploaded={load} />

      <Section title="Recent scans" actions={<Link to="/scans">View all scans</Link>}>
        {recent.length === 0 ? (
          <Empty>
            No scans yet. Upload a firmware image above, or generate samples with <code>make fixtures</code>.
          </Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Firmware</th>
                <th>Platform</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((s) => (
                <tr key={s.id}>
                  <td>
                    <Link to={`/scans/${s.id}`}>{s.original_filename}</Link>
                    <div className="muted">{formatBytes(s.size)}</div>
                  </td>
                  <td>{s.identification?.platform ?? <span className="muted">–</span>}</td>
                  <td>
                    <StatusBadge status={s.status} />
                    {s.status === "running" && <span className="muted"> {s.progress}%</span>}
                  </td>
                  <td>
                    <SeverityCounts counts={s.severity_counts} />
                  </td>
                  <td className="muted nowrap">{formatDate(s.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </div>
  );
}
