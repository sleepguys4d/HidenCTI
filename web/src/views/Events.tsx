import { useEffect, useState } from 'react';
import { api, type SecurityEvent } from '../api';
import { PageHead, Tag, Btn, Icon, SEV_LABEL } from '../components/ui';
import { copilotBus } from '../components/copilotBus';

const FILTERS: { k: string; l: string }[] = [
  { k: 'all', l: 'All' }, { k: 'crit', l: 'Critical' }, { k: 'high', l: 'High' }, { k: 'med', l: 'Medium' },
];

export function Events() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [sev, setSev] = useState('all');
  const [live, setLive] = useState(false);
  useEffect(() => { api.events(sev).then((r) => { setEvents(r.data); setLive(r.live); }).catch(() => {}); }, [sev]);

  return (
    <>
      <PageHead title="Events & Alerts" sub="Unified stream · SIEM · Firewall · NDR · EDR · IDS"
        actions={<>
          <Btn><Icon.pulse size={15} /> {live ? 'Live' : 'Demo'}</Btn>
          <Btn primary onClick={() => copilotBus.ask('Triage the 3 most recent critical alerts and tell me which should become incidents.')}><Icon.spark /> AI triage</Btn>
        </>} />

      <div className="toolbar">
        <div className="filter-grp"><span className="lb">Severity</span>
          {FILTERS.map((f) => <button key={f.k} className={`chip ${sev === f.k ? 'active' : ''}`} onClick={() => setSev(f.k)}>{f.l}</button>)}
        </div>
        <div className="filter-grp" style={{ marginLeft: 'auto' }}><span className="lb">Source</span>
          <span className="src-tag"><span className="d" />Wazuh</span>
          <span className="src-tag"><span className="d" style={{ background: 'var(--high)' }} />OPNsense</span>
          <span className="src-tag"><span className="d" style={{ background: 'var(--low)' }} />Malcolm</span>
          <span className="src-tag"><span className="d" style={{ background: 'var(--med)' }} />Velociraptor</span>
        </div>
      </div>

      <div className="panel">
        <div className="tbl-wrap">
          <table className="dt">
            <thead><tr><th>Time</th><th>Sev</th><th>Source</th><th>Detection</th><th>MITRE</th><th>Host</th><th>Source → Dest</th><th>User</th><th /></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr className="row" key={e.id}
                  onClick={() => copilotBus.ask(`Explain this event and tell me whether to escalate: [${e.time}] ${e.source} — ${e.rule} (${e.technique}) host ${e.host}, ${e.srcIp}->${e.dstIp}, user ${e.user}`)}>
                  <td className="mono dim">{e.time}</td>
                  <td><Tag sev={e.severity}>{SEV_LABEL[e.severity]}</Tag></td>
                  <td><span className="src-tag"><span className="d" />{e.source}</span></td>
                  <td>{e.rule}</td>
                  <td className="mono" style={{ color: 'var(--accent-2)' }}>{e.technique !== '—' ? e.technique : <span className="dim">—</span>}</td>
                  <td className="mono">{e.host}</td>
                  <td className="mono dim">{e.srcIp} → {e.dstIp}</td>
                  <td className="mono">{e.user !== '—' ? e.user : <span className="dim">—</span>}</td>
                  <td><span className="chip" style={{ padding: '4px 9px' }}>⌕ AI</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
