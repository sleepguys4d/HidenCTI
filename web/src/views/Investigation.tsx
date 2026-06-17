import { PageHead, Panel, Btn, Icon, SEV_COLOR } from '../components/ui';
import { copilotBus } from '../components/copilotBus';
import { toast } from '../components/toast';

function Entity({ icon, a, b, risk, score }: { icon: React.ReactNode; a: string; b: string; risk: 'crit' | 'high' | 'med'; score: number }) {
  const dim = { crit: 'var(--crit-dim)', high: 'var(--high-dim)', med: 'var(--med-dim)' }[risk];
  return (
    <div className="entity">
      <div className="ec">{icon}</div>
      <div className="ev"><div className="a">{a}</div><div className="b">{b}</div></div>
      <span className="risk" style={{ color: SEV_COLOR[risk], background: dim }}>{score}</span>
    </div>
  );
}

function TL({ time, crit, title, desc, tag }: { time: string; crit?: boolean; title: string; desc: React.ReactNode; tag: string }) {
  return (
    <div className={`tl-item ${crit ? 'crit' : ''}`}>
      <div className="tl-time">{time} · {tag}</div>
      <div className="tl-title">{title}</div>
      <div className="tl-desc">{desc}</div>
    </div>
  );
}
const HL = ({ children }: { children: React.ReactNode }) => <span className="hl">{children}</span>;

export function Investigation() {
  async function exportCase() {
    try {
      const res = await fetch('/api/incidents', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'INC-2026-0481 · Suspected ransomware · FIN-WS-014', severity: 4 }),
      }).then((x) => x.json());
      toast(`Case exported to TheHive: ${res.id || res.data?.id || 'OK'}`);
    } catch { toast('Could not export case', 'error'); }
  }

  return (
    <>
      <PageHead title="Investigation" sub="Case INC-2026-0481 · Suspected ransomware · FIN-WS-014"
        actions={<>
          <Btn onClick={exportCase}><Icon.case /> Export case</Btn>
          <Btn primary onClick={() => copilotBus.ask('Based on the timeline and entities of case INC-2026-0481, what is the most likely hypothesis and which evidence is still missing?')}><Icon.spark /> AI hypothesis</Btn>
        </>} />

      <div className="inv-grid">
        <div>
          <div style={{ marginBottom: 14 }}>
            <Panel title="Entities" icon={<Icon.target />} meta="6 observables">
              <Entity icon={<Icon.host />} a="FIN-WS-014" b="Compromised endpoint" risk="crit" score={95} />
              <Entity icon={<Icon.user />} a="j.matamba" b="User account" risk="high" score={72} />
              <Entity icon={<Icon.ip />} a="185.220.101.34" b="C2 / Tor exit (MISP)" risk="crit" score={98} />
              <Entity icon={<Icon.ip />} a="45.137.21.8" b="Bruteforce source IP" risk="high" score={64} />
              <Entity icon={<Icon.file />} a="svchost_2.exe" b="Unsigned binary" risk="crit" score={91} />
              <Entity icon={<Icon.host />} a="IT-WS-002" b="Lateral RDP pivot" risk="med" score={55} />
            </Panel>
          </div>
          <Panel title="Threat Intel · MISP" icon={<Icon.intel />}>
            <div className="intel-box">
              <div><span className="dim">Family</span><span style={{ color: 'var(--crit)' }}>LockBit 3.0 (likely)</span></div>
              <div><span className="dim">Confidence</span><span>87%</span></div>
              <div><span className="dim">Correlated IOCs</span><span style={{ color: 'var(--accent)' }}>14</span></div>
              <div><span className="dim">Galaxy</span><span>APT · ransomware</span></div>
            </div>
          </Panel>
        </div>

        <Panel title="Attack timeline" icon={<Icon.pulse />} meta="reconstructed from 7 sources">
          <div className="timeline">
            <TL time="14:18:05" crit tag="T1110 · Suricata" title="Initial access — SSH bruteforce"
              desc={<>240 attempts from <HL>45.137.21.8</HL> against <HL>SRV-LNX-01</HL>. Credential <HL>root</HL> compromised.</>} />
            <TL time="14:21:33" tag="T1210 · Wazuh" title="Lateral SMB exploitation"
              desc={<><HL>EternalBlue</HL> signature targeting FIN-WS-014. Movement from the pivot server.</>} />
            <TL time="14:28:47" crit tag="T1003 · Velociraptor" title="Credential access"
              desc={<>Unsigned process <HL>svchost_2.exe</HL> accesses <HL>LSASS</HL> on FIN-WS-014.</>} />
            <TL time="14:33:10" tag="T1021 · Wazuh" title="Lateral movement via RDP"
              desc={<>RDP session <HL>IT-WS-002 → FIN-WS-014</HL> with account <HL>admin_loc</HL>.</>} />
            <TL time="14:39:51" crit tag="T1071 · Malcolm" title="Command & Control"
              desc={<>Regular beaconing (60s) to <HL>185.220.101.34</HL> — Tor exit confirmed by MISP.</>} />
            <TL time="14:42:08" crit tag="T1490 · Wazuh" title="Impact — ransomware staging"
              desc={<><HL>vssadmin delete shadows</HL> executed. Shadow copies removed. Encryption imminent.</>} />
          </div>
        </Panel>
      </div>
    </>
  );
}
