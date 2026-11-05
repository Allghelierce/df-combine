import { useCallback, useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { Icon } from "./components/ui";
import { api, AppConfig, Me } from "./lib/api";
import Access from "./pages/Access";
import Compare from "./pages/Compare";
import Dashboard from "./pages/Dashboard";
import History from "./pages/History";
import Login from "./pages/Login";
import ScanDetail from "./pages/ScanDetail";
import Tools from "./pages/Tools";

type AuthState = { kind: "loading" } | { kind: "anonymous"; setupRequired: boolean } | { kind: "signed-in"; me: Me };

export default function App() {
  const [auth, setAuth] = useState<AuthState>({ kind: "loading" });
  const [cfg, setCfg] = useState<AppConfig | null>(null);
  const [cfgError, setCfgError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    api
      .me()
      .then((me) => {
        setAuth({ kind: "signed-in", me });
        api.config().then(setCfg).catch((e) => setCfgError(e.message));
      })
      .catch(() => {
        api
          .authStatus()
          .then((s) => setAuth({ kind: "anonymous", setupRequired: s.setup_required }))
          .catch((e) => {
            setCfgError(e.message);
            setAuth({ kind: "anonymous", setupRequired: false });
          });
      });
  }, []);

  useEffect(() => {
    refresh();
    const onUnauthorized = () => setAuth((a) => (a.kind === "signed-in" ? { kind: "anonymous", setupRequired: false } : a));
    window.addEventListener("dfa:unauthorized", onUnauthorized);
    return () => window.removeEventListener("dfa:unauthorized", onUnauthorized);
  }, [refresh]);

  if (auth.kind === "loading") return <div className="empty">Loading…</div>;
  if (auth.kind === "anonymous") return <Login onLogin={refresh} setupRequired={auth.setupRequired} />;

  const me = auth.me;
  const sandboxTone = cfg?.sandbox_mode === "docker" || cfg?.sandbox_mode === "broker" ? "ok" : cfg?.sandbox_mode === "local" ? "warn" : "bad";

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
          <NavLink to="/access">{Icon.shield} Access</NavLink>
        </nav>
        <div className="sidebar-foot">
          {cfg && (
            <div className={`sandbox-pill tone-${sandboxTone}`} title={cfg.sandbox_detail}>
              <span className="dot" /> Sandbox: {cfg.sandbox_mode}
            </div>
          )}
          <div className="user-chip">
            <span className="strong">{me.user?.username ?? "local"}</span> <span className="pill">{me.role}</span>
            {me.user && (
              <button
                className="btn ghost sm"
                onClick={() =>
                  api
                    .logout()
                    .catch(() => undefined)
                    .finally(refresh)
                }
              >
                Sign out
              </button>
            )}
          </div>
          <div className="muted small">v{cfg?.version ?? "…"} · static analysis only</div>
        </div>
      </aside>
      <main className="main">
        {cfgError && <div className="banner bad">Cannot reach the API ({cfgError}).</div>}
        {me.auth_mode === "disabled" && (
          <div className="banner warn">Authentication is disabled (DFA_AUTH_MODE=disabled). Use this only for local, single-user development.</div>
        )}
        {cfg && cfg.sandbox_mode !== "docker" && cfg.sandbox_mode !== "broker" && (
          <div className="banner warn" title={cfg.sandbox_detail}>
            Container isolation is not active: {cfg.sandbox_detail}. Build the sandbox image (see README) for production use.
          </div>
        )}
        <Routes>
          <Route path="/" element={<Dashboard config={cfg} canUpload={me.role !== "viewer"} />} />
          <Route path="/scans" element={<History />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/compare" element={<Compare />} />
          <Route path="/access" element={<Access me={me} />} />
          <Route path="*" element={<div className="empty">Page not found.</div>} />
        </Routes>
      </main>
    </div>
  );
}
