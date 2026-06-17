import { useEffect, useState } from 'react';
import { api } from '../api';
import { PageHead, Btn, Icon } from '../components/ui';
import { copilotBus } from '../components/copilotBus';
import { toast } from '../components/toast';
import { download } from '../lib';

type Action = { time: string; action: string; target: string; incident: string; source: string; status: string };

const PLAYBOOKS = [
  { icon: <Icon.isolate />, t: 'Isolate endpoint', p: 'Cuts the host network connectivity while keeping the EDR channel for forensics. Recommended for FIN-WS-014.', steps: '4 steps', src: 'Velociraptor + OPNsense' },
  { icon: <Icon.block />, t: 'Block IP / domain', p: 'Propagates a block rule to the firewall and DNS sinkhole across all segments.', steps: '3 steps', src: 'OPNsense + MISP' },
  { icon: <Icon.disable />, t: 'Disable account', p: 'Suspends the AD account, revokes active sessions and forces re-authentication.', steps: '3 steps', src: 'Active Directory' },
  { icon: <Icon.quarantine />, t: 'Quarantine file', p: 'Moves the binary to a sandbox, computes the hash and submits it to MISP/Cortex.', steps: '5 steps', src: 'Velociraptor + Cortex' },
  { icon: <Icon.key />, t: 'Reset credentials', p: 'Forces a password change and rotates the service account secrets.', steps: '4 steps', src: 'AD + Vault' },
  { icon: <Icon.shield size={22} />, t: 'Full containment mode', p: 'Applies a restrictive policy to the affected segment and enables enhanced monitoring.', steps: '6 steps', src: 'Orchestrated SOAR' },
];

const stClass: Record<string, string> = { prog: 'st-prog', res: 'st-res', new: 'st-new', cont: 'st-cont' };
const stLabel: Record<string, string> = { prog: 'Running', res: 'Completed', new: 'New', cont: 'Contained' };

export function Response() {
  const [actions, setActions] = useState<Action[]>([]);
  useEffect(() => { api.responseActions().then((r) => setActions(r.data)).catch(() => {}); }, []);

  async function runPb(name: string) {
    try {
      const r = await api.runPlaybook(name, 'FIN-WS-014');
      toast(`Playbook "${name}" started · ticket ${r.ticket}`);
    } catch { toast('Could not start playbook', 'error'); }
  }

  function exportLog() {
    const header = 'time,action,target,incident,source,status';
    const rows = actions.map((a) => [a.time, a.action, a.target, a.incident, a.source, stLabel[a.status] || a.status].join(','));
    download(`response-actions-${new Date().toISOString().slice(0, 10)}.csv`, [header, ...rows].join('\n'), 'text/csv');
    toast('Response action log exported');
  }

  return (
    <>
      <PageHead title="Response & Playbooks" sub="Orchestration and automated response · SOAR · containment actions"
        actions={<>
          <Btn onClick={exportLog}><Icon.download /> Export log</Btn>
          <Btn primary onClick={() => copilotBus.ask('Build a step-by-step response playbook for the ransomware incident INC-2026-0481, from isolation to recovery.')}><Icon.spark /> AI playbook</Btn>
        </>} />

      <div className="pb-grid">
        {PLAYBOOKS.map((pb) => (
          <div className="playbook" key={pb.t}>
            <div className="pb-ic">{pb.icon}</div>
            <h4>{pb.t}</h4><p>{pb.p}</p>
            <div className="pb-foot">
              <span className="pb-steps">{pb.steps} · {pb.src}</span>
              <button className="pb-run" onClick={() => runPb(pb.t)}><Icon.play /> Run</button>
            </div>
          </div>
        ))}
      </div>

      <div className="panel" style={{ marginTop: 14 }}>
        <div className="panel-head"><h3><Icon.pulse size={15} /> Response actions · in progress</h3><span className="meta">Automated SOAR</span></div>
        <div className="tbl-wrap">
          <table className="dt">
            <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Incident</th><th>Source</th><th>Status</th></tr></thead>
            <tbody>
              {actions.map((a, i) => (
                <tr className="row" key={i}>
                  <td className="mono dim">{a.time}</td><td>{a.action}</td>
                  <td className="mono">{a.target}</td><td className="id-cell">{a.incident}</td>
                  <td>{a.source}</td>
                  <td><span className={`status-pill ${stClass[a.status]}`}><span className="sd" />{stLabel[a.status]}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
