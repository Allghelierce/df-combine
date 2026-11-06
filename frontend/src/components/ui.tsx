import { Fragment, ReactNode, useEffect, useRef, useState } from "react";
import type { ScanStatus, Severity } from "../lib/api";
import { capitalize, severityParts, SeverityCountMap } from "../lib/format";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`sev sev-${severity}`}>{capitalize(severity)}</span>;
}

export function StatusBadge({ status }: { status: ScanStatus | string }) {
  return <span className={`status status-${status}`}>{capitalize(status)}</span>;
}

/** "3 critical, 6 high" with each count in its severity colour. */
export function SeverityCounts({ counts }: { counts: SeverityCountMap }) {
  if (!counts) return <span className="muted">–</span>;
  const parts = severityParts(counts);
  if (!parts.length) return <span className="muted">None</span>;
  return (
    <span>
      {parts.map((p, i) => (
        <Fragment key={p.severity}>
          {i > 0 && ", "}
          <span className={`sev-${p.severity}`}>
            {p.n} {p.severity}
          </span>
        </Fragment>
      ))}
    </span>
  );
}

export function Section({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`section ${className}`}>
      {(title || actions) && (
        <header className="section-head">
          {title && <h2>{title}</h2>}
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="error-box" role="alert">
      {msg}
    </div>
  );
}

export function CopyText({ text, display }: { text: string; display?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="copy"
      title="Copy to clipboard"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
    >
      <span className="mono">{display ?? text}</span> <span className="copy-hint">{copied ? "Copied" : "Copy"}</span>
    </button>
  );
}

/** Polls `fn` every `ms` while `active` is true. */
export function usePolling(fn: () => void, ms: number, active: boolean) {
  const saved = useRef(fn);
  saved.current = fn;
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => saved.current(), ms);
    return () => clearInterval(id);
  }, [ms, active]);
}
