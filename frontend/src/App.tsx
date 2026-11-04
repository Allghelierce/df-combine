import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { Icon } from "./components/ui";
import { api, AppConfig, getApiKey, setApiKey } from "./lib/api";
import Compare from "./pages/Compare";
import Dashboard from "./pages/Dashboard";
import History from "./pages/History";
import ScanDetail from "./pages/ScanDetail";
import Tools from "./pages/Tools";

export default function App() {
  const [cfg, setCfg] = useState<AppConfig | null>(null);
  const [cfgError, setCfgError] = useState<string | null>(null);
  const [keyInput, setKeyInput] = useState(getApiKey() ?? "");

  useEffect(() => {
    api
      .config()
      .then(setCfg)
      .catch((e) => setCfgError(e.message));
  }, []);

  const sandboxTone = cfg?.sandbox_mode === "docker" ? "ok" : cfg?.sandbox_mode === "local" ? "warn" : "bad";

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">{Icon.shield}</span>
          <div>
            <div className="brand-name">Drone Firmware</div>
            <div className="brand-sub">Analyzer</div>
          </div>
        </div>
        <nav>
          <NavLink to="/" end>
            {Icon.dash} Dashboard
          </NavLink>
          <NavLink to="/scans">{Icon.history} Scan history</NavLink>
          <NavLink to="/tools">{Icon.tools} Analysis tools</NavLink>
        </nav>
        <div className="sidebar-foot">
          {cfg && (
            <div className={`sandbox-pill tone-${sandboxTone}`} title={cfg.sandbox_detail}>
              <span className="dot" /> Sandbox: {cfg.sandbox_mode}
            </div>
          )}
          <div className="muted small">v{cfg?.version ?? "…"} · static analysis only</div>
        </div>
      </aside>
      <main className="main">
        {cfgError && (
          <div className="banner bad">
            Cannot reach the API ({cfgError}).{" "}
            {cfgError.includes("API key") && (
              <form
                className="inline-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  setApiKey(keyInput || null);
                  window.location.reload();
                }}
              >
                <input type="password" placeholder="API key" value={keyInput} onChange={(e) => setKeyInput(e.target.value)} />
                <button className="btn sm">Save key</button>
              </form>
            )}
          </div>
        )}
        {cfg && cfg.sandbox_mode !== "docker" && (
          <div className="banner warn" title={cfg.sandbox_detail}>
            Container isolation is not active: {cfg.sandbox_detail}. Build the sandbox image (see README) for production use.
          </div>
        )}
        <Routes>
          <Route path="/" element={<Dashboard config={cfg} />} />
          <Route path="/scans" element={<History />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/compare" element={<Compare />} />
          <Route path="*" element={<div className="empty">Page not found.</div>} />
        </Routes>
      </main>
    </div>
  );
}
