import { FormEvent, useCallback, useEffect, useState } from "react";
import { Empty, ErrorBox, Panel } from "../components/ui";
import { api, Me, User } from "../lib/api";
import { formatDate } from "../lib/format";

type Token = Awaited<ReturnType<typeof api.tokens>>["items"][number];

export default function Access({ me }: { me: Me }) {
  const [users, setUsers] = useState<User[]>([]);
  const [tokens, setTokens] = useState<Token[]>([]);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [form, setForm] = useState({ username: "", password: "", role: "analyst" });
  const [label, setLabel] = useState("automation");
  const isAdmin = me.role === "admin";

  const load = useCallback(() => {
    api.tokens().then((t) => setTokens(t.items)).catch(setError);
    if (isAdmin) api.users().then((u) => setUsers(u.items)).catch(setError);
  }, [isAdmin]);
  useEffect(load, [load]);

  async function act(fn: () => Promise<unknown>) {
    setError(null);
    try {
      await fn();
      load();
    } catch (e) {
      setError(e);
    }
  }

  function addUser(e: FormEvent) {
    e.preventDefault();
    void act(async () => {
      await api.createUser(form.username, form.password, form.role);
      setForm({ username: "", password: "", role: "analyst" });
    });
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Access</h1>
          <p className="muted">
            Signed in as <b>{me.user?.username ?? "local user"}</b> ({me.role}). Roles: admin manages users and sees all scans; analyst uploads and
            manages own scans; viewer has read-only access.
          </p>
        </div>
      </header>
      <ErrorBox error={error} />
      <Panel title="API tokens" actions={<span className="muted small">For CI/automation: send as Authorization: Bearer &lt;token&gt;</span>}>
        <form
          className="filter-row"
          onSubmit={(e) => {
            e.preventDefault();
            void act(async () => setNewToken((await api.createToken(label, 90)).token));
          }}
        >
          <input type="text" value={label} onChange={(e) => setLabel(e.target.value)} aria-label="Token label" />
          <button className="btn sm">Create 90-day token</button>
        </form>
        {newToken && (
          <div className="warn-box small">
            Copy this token now; it is stored only as a hash and cannot be shown again:
            <pre className="mono break">{newToken}</pre>
          </div>
        )}
        {tokens.length === 0 ? (
          <Empty>No API tokens.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Label</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => (
                <tr key={t.id}>
                  <td className="strong">{t.label}</td>
                  <td className="small">{formatDate(t.created_at)}</td>
                  <td className="small">{formatDate(t.expires_at)}</td>
                  <td className="small">{formatDate(t.last_used_at)}</td>
                  <td>
                    <button className="btn danger ghost sm" onClick={() => void act(() => api.revokeToken(t.id))}>
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
      {isAdmin && (
        <Panel title="Users">
          <form className="filter-row" onSubmit={addUser}>
            <input type="text" placeholder="username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
            <input
              type="password"
              placeholder="password (min 10 chars)"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              required
              minLength={10}
            />
            <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} aria-label="Role">
              <option value="analyst">analyst</option>
              <option value="viewer">viewer</option>
              <option value="admin">admin</option>
            </select>
            <button className="btn sm">Add user</button>
          </form>
          <table className="table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last login</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td className="strong">{u.username}</td>
                  <td>
                    <select
                      value={u.role}
                      disabled={u.id === me.user?.id}
                      onChange={(e) => void act(() => api.updateUser(u.id, { role: e.target.value }))}
                      aria-label={`Role of ${u.username}`}
                    >
                      <option value="admin">admin</option>
                      <option value="analyst">analyst</option>
                      <option value="viewer">viewer</option>
                    </select>
                  </td>
                  <td>{u.disabled ? <span className="pill bad">disabled</span> : <span className="pill ok">active</span>}</td>
                  <td className="small">{formatDate(u.last_login_at)}</td>
                  <td>
                    {u.id !== me.user?.id && (
                      <button className="btn ghost sm" onClick={() => void act(() => api.updateUser(u.id, { disabled: !u.disabled }))}>
                        {u.disabled ? "Enable" : "Disable"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}
