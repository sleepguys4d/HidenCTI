import { useState } from 'react';
import { api, type AuthUser } from '../api';
import { XpertLogo, Sec4dataSignature } from '../components/Logo';
import { Icon } from '../components/icons';

export function Login({ onLogin }: { onLogin: (u: AuthUser) => void }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!email || !password || busy) return;
    setBusy(true); setErr('');
    try {
      const r = await api.login(email, password);
      if (r.ok && r.user) onLogin(r.user);
      else setErr(r.error || 'Invalid credentials.');
    } catch {
      setErr('Could not reach the server.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <div className="login-grid" />
      <div className="login-card">
        <div className="login-brand"><XpertLogo /></div>
        <div className="login-eyebrow">SECURITY OPERATIONS CONSOLE · RESTRICTED ACCESS</div>
        <h1 className="login-h1">Sign in</h1>
        <div className="login-field">
          <label htmlFor="lemail">Email</label>
          <input id="lemail" type="email" autoFocus value={email} autoComplete="username"
            onChange={(e) => setEmail(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && document.getElementById('lpw')?.focus()}
            placeholder="admin@sec4data.com" />
        </div>
        <div className="login-field">
          <label htmlFor="lpw">Password</label>
          <input id="lpw" type="password" value={password} autoComplete="current-password"
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && submit()}
            placeholder="••••••••" />
        </div>
        {err && <div className="login-err"><Icon.alert size={14} /> {err}</div>}
        <button className="login-btn" onClick={submit} disabled={busy}>
          {busy ? 'Signing in…' : 'Enter console'}
        </button>
        <div className="login-foot">
          <Sec4dataSignature height={18} />
          <span>Encrypted session · Law 22/11</span>
        </div>
      </div>
    </div>
  );
}
