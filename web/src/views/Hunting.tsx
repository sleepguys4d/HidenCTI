import { useEffect, useState } from 'react';
import { api } from '../api';
import { PageHead, Panel, Btn, Tag, Icon, SEV_LABEL } from '../components/ui';
import { copilotBus } from '../components/copilotBus';
import { toast } from '../components/toast';

type Hunt = { name: string; desc: string; tech: string; hosts: string; hits: string };
type HuntResult = Awaited<ReturnType<typeof api.runHunt>>;

const QUERY = (
  <>
    <span className="cm"># Hunt: Lateral movement via RDP + LSASS access (T1021 + T1003)</span>{'\n'}
    <span className="kw">title</span>: RDP lateral movement followed by credential dumping{'\n'}
    <span className="kw">logsource</span>:{'\n'}{'  '}<span className="kw">product</span>: <span className="str">windows</span>{'\n'}{'  '}<span className="kw">service</span>: <span className="str">security</span>{'\n'}
    <span className="kw">detection</span>:{'\n'}{'  '}<span className="fn">rdp_logon</span>:{'\n'}{'    '}EventID: <span className="num">4624</span>{'\n'}{'    '}LogonType: <span className="num">10</span>{'\n'}{'  '}<span className="fn">lsass_access</span>:{'\n'}{'    '}EventID: <span className="num">4656</span>{'\n'}{'    '}ObjectName|endswith: <span className="str">'\lsass.exe'</span>{'\n'}{'  '}<span className="kw">timeframe</span>: <span className="num">10m</span>{'\n'}{'  '}<span className="kw">condition</span>: rdp_logon <span className="kw">and</span> lsass_access{'\n'}
    <span className="kw">level</span>: <span className="str">high</span>{'\n'}
    <span className="cm"># Wazuh equivalent ↓</span>{'\n'}
    <span className="fn">index</span>=wazuh data.win.eventID=<span className="str">"4624"</span> | join host <span className="fn">[search</span> data.win.eventID=<span className="str">"4656"</span> ObjectName=<span className="str">"*lsass*"</span><span className="fn">]</span>
  </>
);

export function Hunting() {
  const [hunts, setHunts] = useState<Hunt[]>([]);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<HuntResult | null>(null);
  useEffect(() => { api.savedHunts().then((r) => setHunts(r.data)).catch(() => {}); }, []);

  async function run() {
    setRunning(true); setResult(null);
    try { setResult(await api.runHunt()); } finally { setRunning(false); }
  }

  function saveHunt() {
    setHunts((h) => [{ name: 'hunt_lateral_lsass', desc: 'RDP lateral movement + LSASS access', tech: 'T1021+T1003', hosts: '14 hosts', hits: '3 hits' }, ...h]);
    toast('Hunt saved to library');
  }

  async function createIncident() {
    try {
      const res = await fetch('/api/incidents', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'Credential dumping detected via hunt (T1003)', severity: 3 }),
      }).then((x) => x.json());
      toast(`Incident created from hunt: ${res.id || res.data?.id || 'OK'}`);
    } catch { toast('Could not create incident', 'error'); }
  }

  return (
    <>
      <PageHead title="Threat Hunting" sub="Proactive hunting console · Sigma · Wazuh QL · KQL · MITRE-driven"
        actions={<>
          <Btn onClick={saveHunt}><Icon.save /> Save hunt</Btn>
          <Btn primary onClick={() => copilotBus.ask('Generate a threat hunting query in Sigma and Wazuh format to detect data exfiltration via DNS tunneling.')}><Icon.spark /> Generate with AI</Btn>
        </>} />

      <div className="hunt-grid">
        <div>
          <div className="console">
            <div className="console-head">
              <div className="dots"><i /><i /><i /></div>
              <span className="ct">hunt_lateral_lsass.sigma</span>
              <span className="lang">SIGMA · WAZUH QL</span>
            </div>
            <div className="editor">{QUERY}</div>
            <div className="console-foot">
              <span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--dim)' }}>Coverage: 1.18M events · 14 hosts in scope</span>
              <Btn primary onClick={run}><Icon.play /> Run hunt</Btn>
            </div>
          </div>

          <Panel title="Results" icon={<Icon.target />} meta={result ? `${result.hits.length} detections · ${result.elapsed}` : running ? 'running…' : 'awaiting execution'}>
            {!result && !running && (
              <div className="hunt-empty"><Icon.play size={20} /><br /><br />Press <b style={{ color: 'var(--accent)' }}>Run hunt</b> to run the query against the unified data lake.</div>
            )}
            {running && (
              <div className="hunt-empty"><div className="typing" style={{ justifyContent: 'center' }}><i /><i /><i /></div><div style={{ marginTop: 12 }}>Running query over 1.18M events…</div></div>
            )}
            {result && (
              <>
                <div className="tbl-wrap">
                  <table className="dt">
                    <thead><tr><th>Host</th><th>RDP Logon</th><th>LSASS Access</th><th>Δ time</th><th>Sev</th></tr></thead>
                    <tbody>
                      {result.hits.map((h) => (
                        <tr className="row" key={h.host}>
                          <td className="mono">{h.host}</td>
                          <td className="mono dim">{h.rdp}</td>
                          <td className="mono dim">{h.lsass}</td>
                          <td className="mono" style={{ color: h.severity === 'crit' ? 'var(--crit)' : 'var(--high)' }}>{h.delta}</td>
                          <td><Tag sev={h.severity}>{SEV_LABEL[h.severity]}</Tag></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div style={{ marginTop: 12, display: 'flex', gap: 9 }}>
                  <Btn primary onClick={() => copilotBus.ask('Analyze these 3 credential-dumping hunt hits and tell me which to turn into incidents.')}><Icon.spark /> Analyze with Copilot</Btn>
                  <Btn onClick={createIncident}><Icon.plus /> Create incident</Btn>
                </div>
              </>
            )}
          </Panel>
        </div>

        <Panel title="Saved hunts" icon={<Icon.layers />}>
          {hunts.map((h) => (
            <div className="saved-hunt" key={h.name} onClick={() => copilotBus.ask(`Explain and optimize this hunt: ${h.name} (${h.tech}).`)}>
              <div className="sh-t">{h.name}<Tag sev="ghost">{h.tech}</Tag></div>
              <div className="sh-d">{h.desc}</div>
              <div className="sh-m"><span>⌖ {h.hosts}</span><span style={{ color: h.hits.startsWith('0') ? 'var(--dim)' : 'var(--high)' }}>● {h.hits}</span></div>
            </div>
          ))}
        </Panel>
      </div>
    </>
  );
}
