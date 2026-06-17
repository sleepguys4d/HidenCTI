export type Severity = 'crit' | 'high' | 'med' | 'low' | 'info';
export type IncidentStatus = 'new' | 'prog' | 'cont' | 'res';
export type HealthState = 'on' | 'deg' | 'off';

export interface SecurityEvent {
  id: string;
  time: string;       // ISO or HH:MM:SS
  severity: Severity;
  source: string;     // Wazuh, OPNsense, Malcolm, MISP...
  rule: string;
  technique: string;  // MITRE ATT&CK id
  host: string;
  srcIp: string;
  dstIp: string;
  user: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  assignee: string;
  sla: string;
  events: number;
}

export interface Integration {
  key: string;
  name: string;
  type: string;
  state: HealthState;
  eps: string;
  version: string;
  rules: string;
  events: string;
}

export interface DashboardSummary {
  threatLevel: string;
  kpis: { label: string; value: string; trend: 'up' | 'down' | 'flat'; note: string; accent?: boolean }[];
  eventVolume: number[];
  severityCounts: { sev: Severity; count: number }[];
  mitre: { tactic: string; id: string; count: number; intensity: number }[];
  geo: { flag: string; country: string; count: number; weight: number }[];
}
