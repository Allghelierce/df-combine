import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
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

  const isolation =
    cfg?.sandbox_mode === "docker"
      ? { tone: "ok", label: "Isolated in Docker" }
      : cfg?.sandbox_mode === "local"
        ? { tone: "warn", label: "No container isolation" }
        : { tone: "bad", label: "Sandbox unavailable" };

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">Drone Firmware Analyzer</div>
        <nav>
          <NavLink to="/" end>
            Upload
          </NavLink>
          <NavLink to="/scans">Scans</NavLink>
          <NavLink to="/tools">Tools</NavLink>
        </nav>
        <div className="sidebar-foot">
          {cfg && (
            <div className={`tone-${isolation.tone}`} title={cfg.sandbox_detail}>
              {isolation.label}
            </div>
          )}
          <div className="muted">Version {cfg?.version ?? "…"}</div>
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
                <button className="btn">Save key</button>
              </form>
            )}
          </div>
        )}
        {cfg && cfg.sandbox_mode !== "docker" && (
          <div className="banner warn" title={cfg.sandbox_detail}>
            Container isolation is off: {cfg.sandbox_detail}. Run <code>make sandbox-image</code> before scanning untrusted firmware.
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
