import type {
  SecurityEvent, Incident, Integration, DashboardSummary,
} from '../types.js';

export const integrations: Integration[] = [
  { key: 'wazuh', name: 'Wazuh', type: 'SIEM / XDR', state: 'on', eps: '18.4k', version: '4.9.2', rules: '3 214', events: '1.18M' },
  { key: 'opnsense', name: 'OPNsense', type: 'Firewall / NGFW', state: 'on', eps: '9.2k', version: '24.7', rules: '842', events: '612k' },
  { key: 'firewall-syslog', name: 'Firewall · Syslog', type: 'Ingestion (push)', state: 'on', eps: '6/min', version: 'RFC 3164/5424', rules: '4 blocks', events: '6' },
  { key: 'webhook', name: 'Inbound Webhook', type: 'Ingestion (push)', state: 'on', eps: '3/min', version: 'JSON / HTTP', rules: 'token', events: '3' },
  { key: 'malcolm', name: 'Malcolm / Zeek', type: 'NDR', state: 'on', eps: '6.7k', version: '24.04', rules: '—', events: '430k' },
  { key: 'velociraptor', name: 'Velociraptor', type: 'EDR', state: 'on', eps: '2.1k', version: '0.73', rules: '118 hunts', events: '88k' },
  { key: 'misp', name: 'MISP', type: 'Threat Intel', state: 'on', eps: '—', version: '2.4', rules: '42k IOCs', events: '—' },
  { key: 'thehive', name: 'TheHive / Cortex', type: 'Case Mgmt / SOAR', state: 'on', eps: '—', version: '5.2', rules: '30 analyzers', events: '—' },
  { key: 'suricata', name: 'Suricata', type: 'IDS / IPS', state: 'deg', eps: '4.1k', version: '7.0', rules: '34 120', events: '290k' },
  { key: 'graylog', name: 'Graylog', type: 'Log Pipeline', state: 'off', eps: '0', version: '6.0', rules: '—', events: '—' },
];

export const events: SecurityEvent[] = [
  { id: 'EVT-1', time: '14:42:08', severity: 'crit', source: 'Wazuh', rule: 'Possible ransomware execution — shadow copies deleted', technique: 'T1490', host: 'FIN-WS-014', srcIp: '10.20.4.14', dstIp: '—', user: 'j.matamba' },
  { id: 'EVT-2', time: '14:39:51', severity: 'crit', source: 'Malcolm', rule: 'C2 beaconing detected (regular 60s interval)', technique: 'T1071', host: 'HR-WS-009', srcIp: '10.20.7.9', dstIp: '185.220.101.34', user: '—' },
  { id: 'EVT-3', time: '14:36:22', severity: 'high', source: 'OPNsense', rule: 'Multiple connections blocked to malicious IP (MISP)', technique: 'T1071', host: '—', srcIp: '10.20.7.9', dstIp: '45.137.21.8', user: '—' },
  { id: 'EVT-4', time: '14:33:10', severity: 'high', source: 'Wazuh', rule: 'Lateral movement via RDP between workstations', technique: 'T1021', host: 'IT-WS-002', srcIp: '10.20.1.2', dstIp: '10.20.4.14', user: 'admin_loc' },
  { id: 'EVT-5', time: '14:28:47', severity: 'high', source: 'Velociraptor', rule: 'LSASS access by an unsigned process', technique: 'T1003', host: 'FIN-WS-014', srcIp: '—', dstIp: '—', user: 'j.matamba' },
  { id: 'EVT-6', time: '14:21:33', severity: 'med', source: 'Suricata', rule: 'SMB exploit attempt (EternalBlue signature)', technique: 'T1210', host: '—', srcIp: '185.220.101.34', dstIp: '10.20.4.14', user: '—' },
  { id: 'EVT-7', time: '14:18:05', severity: 'med', source: 'Wazuh', rule: 'SSH brute-force — 240 attempts in 2min', technique: 'T1110', host: 'SRV-LNX-01', srcIp: '45.137.21.8', dstIp: '10.20.0.10', user: 'root' },
  { id: 'EVT-8', time: '14:12:40', severity: 'med', source: 'OPNsense', rule: 'Outbound traffic to a Tor exit node', technique: 'T1090', host: '—', srcIp: '10.20.7.9', dstIp: '104.244.72.115', user: '—' },
  { id: 'EVT-9', time: '14:05:19', severity: 'low', source: 'Wazuh', rule: 'New local user created after hours', technique: 'T1136', host: 'IT-WS-002', srcIp: '—', dstIp: '—', user: 'admin_loc' },
  { id: 'EVT-10', time: '13:58:02', severity: 'low', source: 'Graylog', rule: 'Password policy changed in AD', technique: 'T1098', host: 'DC-01', srcIp: '—', dstIp: '—', user: 'svc_backup' },
  { id: 'EVT-11', time: '13:51:44', severity: 'info', source: 'Velociraptor', rule: 'Scheduled hunt completed — 0 detections', technique: '—', host: 'fleet', srcIp: '—', dstIp: '—', user: 'soc' },
  { id: 'EVT-12', time: '13:44:11', severity: 'high', source: 'Malcolm', rule: 'Suspected exfiltration — 1.2GB to external destination', technique: 'T1048', host: 'HR-WS-009', srcIp: '10.20.7.9', dstIp: '185.220.101.34', user: '—' },
];

export const incidents: Incident[] = [
  { id: 'INC-2026-0481', title: 'Suspected ransomware — finance workstation FIN-WS-014', severity: 'crit', status: 'new', assignee: 'SA', sla: '12m', events: 7 },
  { id: 'INC-2026-0479', title: 'C2 beaconing + exfiltration on HR-WS-009', severity: 'crit', status: 'prog', assignee: 'PS', sla: '34m', events: 11 },
  { id: 'INC-2026-0476', title: 'Lateral movement via RDP in the IT segment', severity: 'high', status: 'prog', assignee: 'SA', sla: '1h 20m', events: 5 },
  { id: 'INC-2026-0470', title: 'Persistent SSH brute-force on SRV-LNX-01', severity: 'high', status: 'cont', assignee: 'AJ', sla: '2h 10m', events: 4 },
  { id: 'INC-2026-0468', title: 'Service account svc_backup behaving anomalously', severity: 'med', status: 'prog', assignee: 'PS', sla: '3h 45m', events: 3 },
  { id: 'INC-2026-0465', title: 'Tor traffic from a corporate workstation', severity: 'med', status: 'cont', assignee: 'AJ', sla: '—', events: 2 },
  { id: 'INC-2026-0461', title: 'Reported phishing — credentials possibly compromised', severity: 'high', status: 'res', assignee: 'SA', sla: '—', events: 6 },
  { id: 'INC-2026-0457', title: 'SMB exploit blocked at the perimeter', severity: 'low', status: 'res', assignee: 'AJ', sla: '—', events: 1 },
];

export const dashboard: DashboardSummary = {
  threatLevel: 'ELEVATED',
  kpis: [
    { label: 'Events ingested (24h)', value: '3.2M', trend: 'down', note: '▼ 4%' },
    { label: 'Alerts in triage', value: '47', trend: 'up', note: '▲ 12%', accent: true },
    { label: 'Active incidents', value: '8', trend: 'flat', note: '— stable' },
    { label: 'MTTR (avg)', value: '38m', trend: 'down', note: '▼ 9m' },
    { label: 'Sensors online', value: '7/8', trend: 'up', note: '1 degraded' },
  ],
  eventVolume: [42, 55, 38, 61, 72, 48, 90, 66, 58, 74, 82, 95, 70, 63, 88, 52, 77, 91, 68, 84],
  severityCounts: [
    { sev: 'crit', count: 6 }, { sev: 'high', count: 13 }, { sev: 'med', count: 15 },
    { sev: 'low', count: 9 }, { sev: 'info', count: 4 },
  ],
  mitre: [
    { tactic: 'Initial Access', id: 'TA0001', count: 2, intensity: 0.2 },
    { tactic: 'Execution', id: 'TA0002', count: 5, intensity: 0.5 },
    { tactic: 'Persistence', id: 'TA0003', count: 3, intensity: 0.3 },
    { tactic: 'Priv. Esc.', id: 'TA0004', count: 4, intensity: 0.45 },
    { tactic: 'Defense Evasion', id: 'TA0005', count: 6, intensity: 0.7 },
    { tactic: 'Cred. Access', id: 'TA0006', count: 8, intensity: 0.95 },
    { tactic: 'Discovery', id: 'TA0007', count: 3, intensity: 0.3 },
    { tactic: 'Lateral Mov.', id: 'TA0008', count: 7, intensity: 0.8 },
    { tactic: 'Collection', id: 'TA0009', count: 2, intensity: 0.2 },
    { tactic: 'Command & Ctrl', id: 'TA0011', count: 9, intensity: 1 },
    { tactic: 'Exfiltration', id: 'TA0010', count: 5, intensity: 0.55 },
    { tactic: 'Impact', id: 'TA0040', count: 6, intensity: 0.65 },
  ],
  geo: [
    { flag: '🇷🇺', country: 'Russia', count: 412, weight: 1 },
    { flag: '🇨🇳', country: 'China', count: 287, weight: 0.7 },
    { flag: '🇺🇸', country: 'USA', count: 156, weight: 0.4 },
    { flag: '🇳🇱', country: 'Netherlands', count: 98, weight: 0.25 },
    { flag: '🇧🇷', country: 'Brazil', count: 64, weight: 0.18 },
    { flag: '🇦🇴', country: 'Angola (internal)', count: 41, weight: 0.12 },
  ],
};

export const savedHunts = [
  { name: 'Credential Dumping (LSASS)', desc: 'RDP + LSASS access within 10min', tech: 'T1003', hosts: '18 hosts', hits: '3 hits' },
  { name: 'Regular C2 Beaconing', desc: 'Periodic connections to rare destinations', tech: 'T1071', hosts: '—', hits: '2 hits' },
  { name: 'DNS Tunneling', desc: 'Anomalous high-volume TXT/NULL queries', tech: 'T1048', hosts: '—', hits: '0 hits' },
  { name: 'Shadow Copy Deletion', desc: 'vssadmin / wmic delete shadows', tech: 'T1490', hosts: '22 hosts', hits: '1 hit' },
  { name: 'Run Key Persistence', desc: 'Run/RunOnce key modifications', tech: 'T1547', hosts: '—', hits: '5 hits' },
];

export const responseActions = [
  { time: '14:43:02', action: 'Isolate endpoint', target: 'FIN-WS-014', incident: 'INC-2026-0481', source: 'Auto · SOAR', status: 'prog' },
  { time: '14:40:17', action: 'Block IP', target: '185.220.101.34', incident: 'INC-2026-0479', source: 'Analyst · SA', status: 'res' },
  { time: '14:35:50', action: 'Disable account', target: 'admin_loc', incident: 'INC-2026-0476', source: 'Analyst · PS', status: 'res' },
  { time: '14:19:33', action: 'Block IP', target: '45.137.21.8', incident: 'INC-2026-0470', source: 'Auto · SOAR', status: 'res' },
];
