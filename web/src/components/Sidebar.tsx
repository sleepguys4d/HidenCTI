import { Icon } from './icons';

export type ViewKey = 'dashboard' | 'events' | 'incidents' | 'investigation' | 'hunting' | 'response' | 'integrations' | 'settings';

const NAV: { key: ViewKey; label: string; icon: () => JSX.Element }[] = [
  { key: 'dashboard', label: 'Command Center', icon: () => <Icon.dashboard /> },
  { key: 'events', label: 'Events & Alerts', icon: () => <Icon.pulse size={21} /> },
  { key: 'incidents', label: 'Incidents', icon: () => <Icon.alert /> },
  { key: 'investigation', label: 'Investigation', icon: () => <Icon.search /> },
  { key: 'hunting', label: 'Threat Hunting', icon: () => <Icon.hunt /> },
  { key: 'response', label: 'Response & Playbooks', icon: () => <Icon.bolt /> },
];

export function Sidebar({ view, onChange, onCopilot }: { view: ViewKey; onChange: (v: ViewKey) => void; onCopilot: () => void }) {
  return (
    <nav className="sidebar">
      {NAV.map((n) => (
        <button key={n.key} className={`nav-item ${view === n.key ? 'active' : ''}`} onClick={() => onChange(n.key)}>
          {n.icon()}<span className="tip">{n.label}</span>
        </button>
      ))}
      <div className="nav-sep" />
      <button className={`nav-item ${view === 'integrations' ? 'active' : ''}`} onClick={() => onChange('integrations')}>
        <Icon.grid /><span className="tip">Integrations</span>
      </button>
      <div className="nav-spacer" />
      <button className="nav-item" onClick={onCopilot}>
        <Icon.cpu /><span className="tip">SOC Copilot · AI</span>
      </button>
      <button className={`nav-item ${view === 'settings' ? 'active' : ''}`} onClick={() => onChange('settings')}>
        <Icon.cog /><span className="tip">Settings</span>
      </button>
    </nav>
  );
}
