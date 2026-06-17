import { useEffect, useRef, useState } from 'react';
import { api, type SecurityEvent } from '../api';
import { XpertLogo, Sec4dataSignature } from './Logo';
import { Icon } from './icons';
import { copilotBus } from './copilotBus';
import { SEV_COLOR, SEV_LABEL } from './ui';

export function TopBar({ threat, mode, user, onLogout, onNavigate }: {
  threat: string; mode: string;
  user?: { name: string; role: string } | null;
  onLogout?: () => void;
  onNavigate?: (view: string) => void;
}) {
  const [now, setNow] = useState(new Date());
  const [q, setQ] = useState('');
  const [alerts, setAlerts] = useState<SecurityEvent[]>([]);
  const [notifOpen, setNotifOpen] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  // Notificações: alertas crítico/alto recentes do stream unificado.
  const loadAlerts = () => api.events('all')
    .then((r) => setAlerts(r.data.filter((e) => e.severity === 'crit' || e.severity === 'high').slice(0, 8)))
    .catch(() => {});
  useEffect(() => {
    loadAlerts();
    const t = setInterval(loadAlerts, 30000);
    return () => clearInterval(t);
  }, []);

  // Fecha o popover ao clicar fora.
  useEffect(() => {
    const onDoc = (e: MouseEvent) => { if (notifRef.current && !notifRef.current.contains(e.target as Node)) setNotifOpen(false); };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, []);

  const p = (n: number) => String(n).padStart(2, '0');
  const time = `${p(now.getUTCHours())}:${p(now.getUTCMinutes())}:${p(now.getUTCSeconds())}`;
  const date = now.toISOString().slice(0, 10) + ' UTC';
  const badge = alerts.length > 9 ? '9+' : String(alerts.length);

  const runSearch = () => {
    const term = q.trim();
    if (!term) return;
    copilotBus.ask(`Investigate and summarise everything related to: ${term}`);
    setQ('');
  };

  return (
    <header className="topbar">
      <div className="brand">
        <Sec4dataSignature height={30} label={false} />
      </div>
      <XpertLogo />
      <div className="tb-spacer" />
      <div className="search">
        <Icon.search size={14} />
        <input placeholder="Search IOC, host, IP, incident, CVE..." value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && runSearch()} />
        <kbd>⌘K</kbd>
      </div>
      <div className="threat-pill">
        <span className="dot" />
        <div><div className="tl">POSTURE</div><div className="tv">{threat}</div></div>
      </div>
      <div className="mode-pill" title="Data source">
        <span className={`md ${mode}`} />{mode === 'live' ? 'LIVE' : 'DEMO'}
      </div>
      <div className="clock"><b>{time}</b><br /><span>{date}</span></div>

      <div className="notif" ref={notifRef}>
        <button className="tb-btn" title="Alerts" onClick={() => setNotifOpen((o) => !o)}>
          <Icon.bell />{alerts.length > 0 && <span className="badge">{badge}</span>}
        </button>
        {notifOpen && (
          <div className="notif-pop">
            <div className="np-head">
              <span>Active alerts</span>
              <span className="np-count">{alerts.length} high / critical</span>
            </div>
            <div className="np-body">
              {alerts.length === 0 && <div className="np-empty">No high-severity alerts right now.</div>}
              {alerts.map((a) => (
                <button className="np-item" key={a.id}
                  onClick={() => { setNotifOpen(false); onNavigate?.('events'); }}>
                  <span className="np-sev" style={{ background: SEV_COLOR[a.severity] }} />
                  <span className="np-txt">
                    <span className="np-rule">{a.rule}</span>
                    <span className="np-meta">{a.source} · {a.host} · {a.time}</span>
                  </span>
                  <span className="np-tag" style={{ color: SEV_COLOR[a.severity] }}>{SEV_LABEL[a.severity]}</span>
                </button>
              ))}
            </div>
            <button className="np-foot" onClick={() => { setNotifOpen(false); onNavigate?.('events'); }}>
              View all events →
            </button>
          </div>
        )}
      </div>

      <div className="tb-user">
        <button className="avatar" title="Settings" onClick={() => onNavigate?.('settings')}>
          {(user?.name || 'SA').split(' ').map((w) => w[0]).slice(0, 2).join('').toUpperCase()}
        </button>
        {onLogout && user && (
          <button className="tb-logout" title="Sign out" onClick={onLogout}><Icon.logout /></button>
        )}
      </div>
    </header>
  );
}
