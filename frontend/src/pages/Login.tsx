import { FormEvent, useState } from "react";
import { Icon } from "../components/ui";
import { api } from "../lib/api";

export default function Login({ onLogin, setupRequired }: { onLogin: () => void; setupRequired: boolean }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(username, password);
      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="login panel" onSubmit={submit} aria-label="Sign in">
        <div className="brand login-brand">
          <span className="brand-mark">{Icon.shield}</span>
          <div>
            <div className="brand-name">Drone Firmware</div>
            <div className="brand-sub">Analyzer</div>
          </div>
        </div>
        {setupRequired ? (
          <div className="warn-box small">
            No accounts exist yet. Create an administrator on the server:
            <pre className="mono">python -m dfa.cli create-user admin --role admin</pre>
            or start the API with DFA_BOOTSTRAP_ADMIN / DFA_BOOTSTRAP_ADMIN_PASSWORD.
          </div>
        ) : null}
        <label>
          Username
          <input type="text" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </label>
        <label>
          Password
          <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        {error && (
          <div className="error-box" role="alert">
            {error}
          </div>
        )}
        <button className="btn" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
