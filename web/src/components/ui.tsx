import type { ReactNode } from 'react';
import type { Severity, IncidentStatus, HealthState } from '../api';
import { Icon } from './icons';

export const SEV_LABEL: Record<Severity, string> = { crit: 'Critical', high: 'High', med: 'Medium', low: 'Low', info: 'Info' };
export const SEV_COLOR: Record<Severity, string> = { crit: 'var(--crit)', high: 'var(--high)', med: 'var(--med)', low: 'var(--low)', info: 'var(--info)' };
export const ST_MAP: Record<IncidentStatus, { c: string; l: string }> = {
  new: { c: 'st-new', l: 'New' }, prog: { c: 'st-prog', l: 'In Progress' },
  cont: { c: 'st-cont', l: 'Contained' }, res: { c: 'st-res', l: 'Resolved' },
};
export const healthLabel = (s: HealthState) => (s === 'on' ? 'Online' : s === 'deg' ? 'Degraded' : 'Offline');

export function PageHead({ title, sub, actions }: { title: string; sub: string; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <div className="page-title"><span className="br">[</span>{title}<span className="br">]</span></div>
        <div className="page-sub">{sub}</div>
      </div>
      <div className="head-actions">{actions}</div>
    </div>
  );
}

export function Panel({ title, icon, meta, children, action }: { title: string; icon?: ReactNode; meta?: ReactNode; children: ReactNode; action?: ReactNode }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <h3>{icon}{title}</h3>
        {action || (meta && <span className="meta">{meta}</span>)}
      </div>
      <div className="panel-body">{children}</div>
    </div>
  );
}

export function Tag({ sev, children }: { sev: Severity | 'ghost'; children: ReactNode }) {
  return <span className={`tag ${sev}`}>{children}</span>;
}

export function StatusPill({ status }: { status: IncidentStatus }) {
  const s = ST_MAP[status];
  return <span className={`status-pill ${s.c}`}><span className="sd" />{s.l}</span>;
}

export function Btn({ primary, onClick, children }: { primary?: boolean; onClick?: () => void; children: ReactNode }) {
  return <button className={`btn ${primary ? 'primary' : ''}`} onClick={onClick}>{children}</button>;
}

export function HealthDot({ state }: { state: HealthState }) {
  return <span className={`sdot ${state}`} />;
}

export { Icon };
