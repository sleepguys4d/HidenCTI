import { config } from '../../config.js';
import { ingest, _bufferLength } from './store.js';

/**
 * Em modo DEMO, injeta algumas linhas de syslog reais (formato OPNsense,
 * FortiGate e Cisco ASA) através do parser verdadeiro, para que a consola
 * mostre eventos de firewall e estatísticas mesmo sem uma firewall ligada.
 */
const DEMO_LINES: string[] = [
  // OPNsense / pfSense filterlog (CSV) — bloqueio de entrada para porta RDP
  '<134>filterlog: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,185.220.101.34,10.20.4.14,49231,3389,0,S',
  // OPNsense — saída bloqueada para Tor exit node
  '<134>filterlog: 7,,,1000000110,igb1,match,block,out,4,0x0,,64,55012,0,DF,6,tcp,52,10.20.7.9,104.244.72.115,51020,443,0,S',
  // FortiGate (key=value) — sessão negada
  '<189>devname=FGT-LUANDA devid=FG100F srcip=45.137.21.8 dstip=10.20.0.10 srcport=44120 dstport=22 proto=6 action=deny service=SSH policyid=12 msg="SSH brute-force blocked"',
  // FortiGate — tráfego permitido (web)
  '<190>devname=FGT-LUANDA srcip=10.20.1.50 dstip=142.250.200.14 srcport=51234 dstport=443 proto=6 action=accept service=HTTPS',
  // Cisco ASA — deny
  '<165>%ASA-4-106023: Deny tcp src outside:185.220.101.34/49231 dst inside:10.20.4.14/445 by access-group "outside_in"',
  // OPNsense — bloqueio de scan a partir de IP malicioso conhecido
  '<134>filterlog: 9,,,1000000122,igb0,match,block,in,4,0x0,,64,22001,0,DF,6,tcp,44,45.137.21.8,10.20.0.10,40221,3306,0,S',
];

export function seedSyslogDemo(): void {
  if (!config.demoMode) return;
  if (_bufferLength() > 0) return; // já há dados reais — não mistura
  const base = Date.now();
  DEMO_LINES.forEach((line, i) => {
    // Distribui os timestamps de origem (remetente fictício na rede de gestão).
    void base; void i;
    ingest(line, '10.20.0.1');
  });
}
