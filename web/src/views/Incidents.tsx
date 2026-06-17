import { useEffect, useState } from 'react';
import { api, type Incident, type IncidentStatus } from '../api';
import { PageHead, Btn, Icon, SEV_COLOR } from '../components/ui';
import { copilotBus } from '../components/copilotBus';
import { toast } from '../components/toast';

const COLS: { k: IncidentStatus; l: string; dot: string }[] = [
  { k: 'new', l: 'New', dot: 'var(--crit)' },
  { k: 'prog', l: 'In Progress', dot: 'var(--med)' },
  { k: 'cont', l: 'Contained', dot: 'var(--accent-2)' },
  { k: 'res', l: 'Resolved', dot: 'var(--low)' },
];

export function Incidents() {
  const [inc, setInc] = useState<Incident[]>([]);
  const load = () => api.incidents().then((r) => setInc(r.data)).catch(() => {});
  useEffect(() => { load(); }, []);

  async function create() {
    try {
      const res = await fetch('/api/incidents', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: 'Manual incident', severity: 2 }) }).then((x) => x.json());
      toast(`Incident created: ${res.id || res.data?.id || 'OK'}`);
      load();
    } catch { toast('Could not create incident', 'error'); }
  }

  return (
    <>
      <PageHead title="Incident Management" sub="Unified case management · SLA · assignment · event chain"
        actions={<>
          <Btn onClick={create}><Icon.plus /> New incident</Btn>
          <Btn primary onClick={() => copilotBus.ask('Give me an executive summary of the open critical incidents and a prioritization recommendation.')}><Icon.spark /> AI briefing</Btn>
        </>} />

      <div className="kanban">
        {COLS.map((c) => {
          const items = inc.filter((i) => i.status === c.k);
          return (
            <div className="kcol" key={c.k}>
              <div className="kcol-head">
                <div className="kt"><span className="sdot" style={{ background: c.dot, boxShadow: `0 0 8px ${c.dot}` }} />{c.l}</div>
                <span className="kc">{items.length}</span>
              </div>
              <div className="kcol-body">
                {items.length === 0 && <div className="kempty">no cases</div>}
                {items.map((i) => (
                  <div className="kcard" key={i.id} onClick={() => copilotBus.ask(`Summarize incident ${i.id} — ${i.title} — and outline the next steps.`)}>
                    <span className="sevbar" style={{ background: SEV_COLOR[i.severity] }} />
                    <div className="kid">{i.id}</div>
                    <div className="ktl">{i.title}</div>
                    <div className="kmeta">
                      <span className="assignee"><span className="ab">{i.assignee}</span></span>
                      <span className="ksla">{i.sla !== '—' ? <><Icon.clock /> SLA {i.sla}</> : <span style={{ color: 'var(--low)' }}>✓ closed</span>}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </>
  );
}
