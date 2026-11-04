import { SEVERITIES, Severity } from "../lib/api";
import { riskLabel } from "../lib/format";

const SEV_VAR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

/** Donut of findings per severity, with the total in the middle. */
export function SeverityDonut({ counts, size = 168 }: { counts: Partial<Record<Severity, number>>; size?: number }) {
  const total = SEVERITIES.reduce((a, s) => a + (counts[s] ?? 0), 0);
  const r = size / 2 - 14;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="donut-wrap">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`${total} findings by severity`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--track)" strokeWidth="16" />
        {total > 0 &&
          SEVERITIES.map((s) => {
            const n = counts[s] ?? 0;
            if (!n) return null;
            const len = (n / total) * c;
            const gap = total > n ? 2 : 0;
            const el = (
              <circle
                key={s}
                cx={size / 2}
                cy={size / 2}
                r={r}
                fill="none"
                stroke={SEV_VAR[s]}
                strokeWidth="16"
                strokeDasharray={`${Math.max(len - gap, 0.5)} ${c - Math.max(len - gap, 0.5)}`}
                strokeDashoffset={-offset}
                transform={`rotate(-90 ${size / 2} ${size / 2})`}
              >
                <title>{`${s}: ${n}`}</title>
              </circle>
            );
            offset += len;
            return el;
          })}
        <text x="50%" y="47%" textAnchor="middle" className="donut-total">
          {total}
        </text>
        <text x="50%" y="62%" textAnchor="middle" className="donut-caption">
          findings
        </text>
      </svg>
      <ul className="legend">
        {SEVERITIES.map((s) => (
          <li key={s}>
            <span className="swatch" style={{ background: SEV_VAR[s] }} />
            <span className="legend-label">{s}</span>
            <span className="legend-value">{counts[s] ?? 0}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function RiskGauge({ score }: { score: number | null }) {
  const { label, tone } = riskLabel(score);
  const pct = Math.max(0, Math.min(100, score ?? 0));
  const r = 52;
  const c = Math.PI * r;
  return (
    <div className={`gauge tone-${tone}`} title="Heuristic 0-100 score from severity and evidence class; not a probability">
      <svg width="132" height="78" viewBox="0 0 132 78" role="img" aria-label={`Risk score ${score ?? "n/a"}`}>
        <path d="M14 70 A52 52 0 0 1 118 70" fill="none" stroke="var(--track)" strokeWidth="11" strokeLinecap="round" />
        <path
          d="M14 70 A52 52 0 0 1 118 70"
          fill="none"
          stroke="currentColor"
          strokeWidth="11"
          strokeLinecap="round"
          strokeDasharray={`${(pct / 100) * c} ${c}`}
        />
        <text x="66" y="62" textAnchor="middle" className="gauge-value">
          {score ?? "–"}
        </text>
      </svg>
      <div className="gauge-label">Risk: {label}</div>
    </div>
  );
}

export function StackedBar({ items }: { items: { key: string; value: number; color: string; label: string }[] }) {
  const total = items.reduce((a, b) => a + b.value, 0);
  return (
    <div className="stacked">
      <div className="stacked-bar" role="img" aria-label="distribution">
        {total === 0 ? (
          <span className="stacked-empty" />
        ) : (
          items.map((i) =>
            i.value ? (
              <span key={i.key} style={{ width: `${(100 * i.value) / total}%`, background: i.color }} title={`${i.label}: ${i.value}`} />
            ) : null,
          )
        )}
      </div>
      <div className="stacked-legend">
        {items.map((i) => (
          <span key={i.key}>
            <span className="swatch" style={{ background: i.color }} /> {i.label} <b>{i.value}</b>
          </span>
        ))}
      </div>
    </div>
  );
}

export function MiniSeverity({ counts }: { counts: Partial<Record<Severity, number>> | null }) {
  if (!counts) return <span className="muted">–</span>;
  return (
    <span className="mini-sev">
      {SEVERITIES.filter((s) => s !== "info").map((s) => (
        <span key={s} className={`mini sev-${s} ${counts[s] ? "" : "zero"}`} title={s}>
          {counts[s] ?? 0}
        </span>
      ))}
    </span>
  );
}
