import { useEffect, useMemo, useState } from 'react';
import { api, type AuthUser, type ManagedUser } from '../api';
import { PageHead, Panel, Btn, Icon } from '../components/ui';
import { toast } from '../components/toast';

const ROLES = ['OWNER', 'ADMIN', 'ANALYST', 'VIEWER', 'AUDITOR'];

export function Settings({ user, mode, authRequired }: { user: AuthUser | null; mode: string; authRequired: boolean }) {
  const canManage = Boolean(user && (user.role === 'OWNER' || user.role === 'ADMIN'));

  return (
    <>
      <PageHead title="Settings" sub="Tenant, account and access management" />

      <div className="set-grid">
        <Panel title="Tenant" icon={<Icon.shield size={15} />}>
          <div className="kv-list">
            <div className="kv"><span>Organization</span><b>SOC Xpert · Sec4data</b></div>
            <div className="kv"><span>Data mode</span><b className={mode === 'live' ? 'ok' : ''}>{mode.toUpperCase()}</b></div>
            <div className="kv"><span>Authentication</span><b>{authRequired ? 'Required' : 'Open (demo)'}</b></div>
          </div>
        </Panel>
        <Panel title="Your account" icon={<Icon.user size={15} />}>
          <div className="kv-list">
            <div className="kv"><span>Name</span><b>{user?.name || 'SOC Analyst'}</b></div>
            <div className="kv"><span>Email</span><b>{user?.email || '—'}</b></div>
            <div className="kv"><span>Role</span><b>{user?.role || '—'}</b></div>
          </div>
        </Panel>
      </div>

      <UserManagement canManage={canManage} authRequired={authRequired} currentEmail={user?.email} />
    </>
  );
}

function UserManagement({ canManage, authRequired, currentEmail }: { canManage: boolean; authRequired: boolean; currentEmail?: string }) {
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [available, setAvailable] = useState(true);
  const [creating, setCreating] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const load = () => api.users().then((r) => { setUsers(r.data); setAvailable(r.available); setLoaded(true); }).catch(() => setLoaded(true));
  useEffect(() => { if (canManage) load(); }, [canManage]);

  if (authRequired && !canManage) {
    return <Panel title="Users" icon={<Icon.user size={15} />}><div className="set-note">You need an Owner or Admin role to manage users.</div></Panel>;
  }
  if (!authRequired) {
    return <Panel title="Users" icon={<Icon.user size={15} />}><div className="set-note">User management activates once login is enabled (set an admin account — see deployment guide).</div></Panel>;
  }

  const setRole = async (u: ManagedUser, role: string) => {
    await api.updateUser(u.id, { role });
    toast(`${u.name} is now ${role}`); load();
  };
  const toggleStatus = async (u: ManagedUser) => {
    if (u.status === 'ACTIVE') {
      const r = await api.deleteUser(u.id);
      if (r.ok) { toast(`${u.name} deactivated`, 'info'); } else { toast(r.error || 'Could not deactivate', 'error'); }
    } else {
      await api.updateUser(u.id, { status: 'ACTIVE' });
      toast(`${u.name} reactivated`);
    }
    load();
  };

  return (
    <>
      <Panel title="Users" icon={<Icon.user size={15} />} meta={`${users.length} accounts`}
        action={<button className="mini cfg" onClick={() => setCreating(true)}><Icon.plus size={14} /> New user</button>}>
        {!available && <div className="set-note">User management requires a database. Deploy with PostgreSQL (see the production guide).</div>}
        {available && loaded && users.length === 0 && <div className="set-note">No users yet. Create the first one.</div>}
        {available && users.length > 0 && (
          <div className="tbl-wrap">
            <table className="dt">
              <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th /></tr></thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>{u.name}{u.email === currentEmail && <span className="self-tag">you</span>}</td>
                    <td className="mono dim">{u.email}</td>
                    <td>
                      <select className="role-sel" value={u.role} onChange={(e) => setRole(u, e.target.value)}>
                        {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </td>
                    <td><span className={`status-pill ${u.status === 'ACTIVE' ? 'st-res' : 'st-new'}`}><span className="sd" />{u.status === 'ACTIVE' ? 'Active' : 'Disabled'}</span></td>
                    <td>
                      {u.email !== currentEmail &&
                        <button className="mini" onClick={() => toggleStatus(u)}>{u.status === 'ACTIVE' ? 'Deactivate' : 'Reactivate'}</button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      {creating && <NewUserModal onClose={() => setCreating(false)} onCreated={() => { setCreating(false); load(); }} />}
    </>
  );
}

function NewUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [f, setF] = useState({ name: '', email: '', password: '', role: 'ANALYST' });
  const [busy, setBusy] = useState(false);
  const set = (k: string, v: string) => setF((p) => ({ ...p, [k]: v }));
  const valid = useMemo(() => f.name && /.+@.+\..+/.test(f.email) && f.password.length >= 8, [f]);

  const save = async () => {
    setBusy(true);
    try {
      const r = await api.createUser(f);
      if (r.ok) { toast(`User ${f.name} created`); onCreated(); }
      else toast(r.error || 'Could not create user', 'error');
    } finally { setBusy(false); }
  };

  return (
    <div className="modal-ov" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="mhead">
          <div className="ci"><Icon.user size={19} /></div>
          <div><div className="t">New user</div><div className="s">Create a console account</div></div>
          <button className="x" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="mbody">
          <div className="field"><label>Full name<span className="req">*</span></label>
            <input type="text" value={f.name} onChange={(e) => set('name', e.target.value)} placeholder="Samuel Ajayi" autoComplete="off" /></div>
          <div className="field"><label>Email<span className="req">*</span></label>
            <input type="email" value={f.email} onChange={(e) => set('email', e.target.value)} placeholder="samuel@sec4data.com" autoComplete="off" /></div>
          <div className="field"><label>Password<span className="req">*</span></label>
            <input type="password" value={f.password} onChange={(e) => set('password', e.target.value)} placeholder="At least 8 characters" autoComplete="new-password" /></div>
          <div className="field"><label>Role</label>
            <select className="role-sel wide" value={f.role} onChange={(e) => set('role', e.target.value)}>
              {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
        </div>
        <div className="mfoot">
          <span className="grow" />
          <button className="mini" onClick={onClose}>Cancel</button>
          <Btn primary onClick={valid && !busy ? save : undefined}>{busy ? 'Creating…' : valid ? 'Create user' : 'Fill required fields'}</Btn>
        </div>
      </div>
    </div>
  );
}
