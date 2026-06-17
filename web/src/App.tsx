import { useEffect, useState } from 'react';
import { api, type AuthUser } from './api';
import { TopBar } from './components/TopBar';
import { Sidebar, type ViewKey } from './components/Sidebar';
import { Copilot } from './components/Copilot';
import { Toaster } from './components/toast';
import { copilotBus } from './components/copilotBus';
import { Icon } from './components/icons';
import { Sec4dataSignature } from './components/Logo';
import { Login } from './views/Login';
import { Dashboard } from './views/Dashboard';
import { Events } from './views/Events';
import { Incidents } from './views/Incidents';
import { Investigation } from './views/Investigation';
import { Hunting } from './views/Hunting';
import { Response } from './views/Response';
import { Integrations } from './views/Integrations';
import { Settings } from './views/Settings';

export default function App() {
  const [view, setView] = useState<ViewKey>('dashboard');
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [threat, setThreat] = useState('ELEVATED');
  const [mode, setMode] = useState('demo');
  const [auth, setAuth] = useState<{ loading: boolean; required: boolean; user: AuthUser | null }>({ loading: true, required: false, user: null });

  useEffect(() => {
    api.me()
      .then((s) => setAuth({ loading: false, required: s.authRequired, user: s.user }))
      .catch(() => setAuth({ loading: false, required: false, user: null }));
  }, []);

  const authed = !auth.required || Boolean(auth.user);

  useEffect(() => {
    if (!authed) return;
    api.dashboard().then((d) => { setThreat(d.threatLevel); setMode(d.mode); }).catch(() => {});
  }, [authed]);

  const logout = async () => {
    try { await api.logout(); } catch { /* ignore */ }
    setAuth((a) => ({ ...a, user: null }));
    setView('dashboard');
  };

  useEffect(() => copilotBus.subscribe(() => setCopilotOpen(true)), []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); (document.querySelector('.search input') as HTMLInputElement)?.focus(); }
      if (e.key === 'Escape') setCopilotOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const VIEWS: Record<ViewKey, JSX.Element> = {
    dashboard: <Dashboard go={(v) => setView(v as ViewKey)} />,
    events: <Events />,
    incidents: <Incidents />,
    investigation: <Investigation />,
    hunting: <Hunting />,
    response: <Response />,
    integrations: <Integrations />,
    settings: <Settings user={auth.user} mode={mode} authRequired={auth.required} />,
  };

  if (auth.loading) {
    return <div className="boot-splash"><div className="boot-ring" /><span>SOC Xpert</span></div>;
  }
  if (auth.required && !auth.user) {
    return <><Login onLogin={(u) => setAuth((a) => ({ ...a, user: u }))} /><Toaster /></>;
  }

  return (
    <>
      <div className="grid-overlay" />
      <div className="scanlines" />
      <div className="app">
        <TopBar threat={threat} mode={mode} user={auth.user} onLogout={auth.required ? logout : undefined} onNavigate={(v) => setView(v as ViewKey)} />
        <Sidebar view={view} onChange={setView} onCopilot={() => setCopilotOpen(true)} />
        <main className="workspace">
          {VIEWS[view]}
          <footer className="app-foot"><Sec4dataSignature height={20} /><span className="foot-v">SOC Xpert v1.0 · {mode.toUpperCase()}</span></footer>
        </main>
      </div>

      {!copilotOpen && (
        <button className="copilot-fab" onClick={() => setCopilotOpen(true)}>
          <span className="ring" /><Icon.cpu size={26} />
        </button>
      )}
      <Copilot open={copilotOpen} onClose={() => setCopilotOpen(false)} />
      <Toaster />
    </>
  );
}
