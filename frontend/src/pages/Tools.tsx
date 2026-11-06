import { useEffect, useState } from "react";
import { ErrorBox } from "../components/ui";
import { api, ToolStatus } from "../lib/api";

const NOTES: Record<string, string> = {
  builtin:
    "Runs inside the sandbox for every scan: content-based format detection, recursive safe extraction, PX4/ArduPilot identification, secrets, insecure configuration, drone parameter and MAVLink exposure checks, ELF hardening and component version checks.",
  fwanalyzer:
    "Linux filesystem policy checks (setuid, world-writable, disallowed files, config content). Applies to companion-computer (Linux) images, not to PX4 or ArduPilot flight-controller binaries.",
  cwe_checker:
    "Ghidra-based static analysis of ELF binaries for CWE patterns. Warnings are reported as unverified. Raw Cortex-M images require experimental bare-metal mode (DFA_CWE_CHECKER_BARE_METAL=true).",
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
          <h1>Tools</h1>
          <p className="lede">Which analysis tools this server can run right now. Each scan decides per tool whether it applies.</p>
        </div>
        <button className="btn" onClick={load} disabled={loading}>
          {loading ? "Checking…" : "Check again"}
        </button>
      </header>
      <ErrorBox error={error} />
      {(tools ?? []).map((t) => {
        const state = t.available ? { tone: "ok", word: "Available" } : t.enabled ? { tone: "warn", word: "Unavailable" } : { tone: "muted", word: "Not configured" };
        return (
          <section key={t.name} className="section tool">
            <h2>
              {t.display_name} <span className={`tone-${state.tone}`}>{state.word}</span>
            </h2>
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
                      {t.homepage.replace(/^https?:\/\//, "")}
                    </a>
                  </dd>
                </>
              )}
            </dl>
          </section>
        );
      })}
    </div>
  );
}
