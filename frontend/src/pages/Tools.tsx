import { useEffect, useState } from "react";
import { ErrorBox, Panel } from "../components/ui";
import { api, ToolStatus } from "../lib/api";

const NOTES: Record<string, string> = {
  builtin:
    "Runs inside the sandbox for every scan: content-based format detection, recursive safe extraction, PX4/ArduPilot identification, secrets, insecure configuration, drone parameter and MAVLink exposure checks, ELF hardening and component version checks.",
  fwanalyzer:
    "Linux filesystem policy checks (setuid, world-writable, disallowed files, config content). Only applicable to companion-computer / Linux images — not to PX4/ArduPilot MCU binaries.",
  cwe_checker:
    "Ghidra-based static analysis of ELF binaries for CWE patterns. Warnings are reported as unverified. Raw Cortex-M images require experimental bare-metal mode (DFA_CWE_CHECKER_BARE_METAL=true).",
  fact: "Full firmware analysis platform integrated through its REST API. Requires a separately deployed FACT instance (DFA_FACT_URL).",
};

export default function Tools() {
  const [tools, setTools] = useState<ToolStatus[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);

  function load() {
    setLoading(true);
    api
      .tools()
      .then((t) => {
        setTools(t.tools);
        setError(null);
      })
      .catch(setError)
      .finally(() => setLoading(false));
  }
  useEffect(load, []);

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Analysis tools</h1>
          <p className="muted">Live availability of each analysis engine on this server. Tools are not interchangeable; each scan decides per tool whether it applies.</p>
        </div>
        <button className="btn ghost" onClick={load} disabled={loading}>
          {loading ? "Checking…" : "Re-check"}
        </button>
      </header>
      <ErrorBox error={error} />
      <div className="tool-grid">
        {(tools ?? []).map((t) => (
          <Panel
            key={t.name}
            className="tool-card"
            title={
              <>
                <span className={`dot ${t.available ? "ok" : t.enabled ? "warn" : "muted"}`} /> {t.display_name}
              </>
            }
            actions={<span className={`pill ${t.available ? "ok" : "warn"}`}>{t.available ? "available" : t.enabled ? "unavailable" : "not configured"}</span>}
          >
            <p>{NOTES[t.name]}</p>
            <dl className="kv">
              <dt>Status</dt>
              <dd>{t.detail}</dd>
              {t.mode && (
                <>
                  <dt>Mode</dt>
                  <dd className="mono">{t.mode}</dd>
                </>
              )}
              {t.version && (
                <>
                  <dt>Version</dt>
                  <dd className="mono">{t.version}</dd>
                </>
              )}
              {t.inputs && (
                <>
                  <dt>Inputs</dt>
                  <dd>{t.inputs}</dd>
                </>
              )}
              {t.homepage && (
                <>
                  <dt>Project</dt>
                  <dd>
                    <a href={t.homepage} target="_blank" rel="noreferrer noopener">
                      {t.homepage}
                    </a>
                  </dd>
                </>
              )}
            </dl>
          </Panel>
        ))}
      </div>
    </div>
  );
}
