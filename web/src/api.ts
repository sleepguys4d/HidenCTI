export type Severity = 'crit' | 'high' | 'med' | 'low' | 'info';
export type IncidentStatus = 'new' | 'prog' | 'cont' | 'res';
export type HealthState = 'on' | 'deg' | 'off';

export interface SecurityEvent {
  id: string; time: string; severity: Severity; source: string; rule: string;
  technique: string; host: string; srcIp: string; dstIp: string; user: string;
}
export interface Incident {
  id: string; title: string; severity: Severity; status: IncidentStatus;
  assignee: string; sla: string; events: number;
}
export interface Integration {
  key: string; name: string; type: string; state: HealthState;
  eps: string; version: string; rules: string; events: string;
}
export interface ConnectorField {
  name: string; label: string; type: 'text' | 'url' | 'password' | 'bool';
  required: boolean; secret: boolean; placeholder?: string; help?: string;
  value: string | boolean; isSet?: boolean;
}
export interface ConnectorSpec {
  key: string; label: string; category: string;
  push: boolean; pull: boolean; testable: boolean;
  enabled: boolean; configured: boolean; source: 'env' | 'db' | 'memory';
  fields: ConnectorField[];
}
export interface TestResult { ok: boolean; state: HealthState; message: string }
export interface AuthUser { id: string; email: string; name: string; role: string }
export interface AuthState { authRequired: boolean; user: AuthUser | null }
export interface ManagedUser { id: string; email: string; name: string; role: string; status: string; createdAt: string }
export interface Dashboard {
  threatLevel: string; mode: string;
  kpis: { label: string; value: string; trend: 'up' | 'down' | 'flat'; note: string; accent?: boolean }[];
  eventVolume: number[];
  severityCounts: { sev: Severity; count: number }[];
  mitre: { tactic: string; id: string; count: number; intensity: number }[];
  geo: { flag: string; country: string; count: number; weight: number }[];
  integrations: Integration[];
}

const BASE = '/api';

async function get<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE}${path}`, { credentials: 'include' });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
async function post<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(`${BASE}${path}`, {
    method: 'POST', credentials: 'include',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
async function del<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE}${path}`, { method: 'DELETE', credentials: 'include' });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

export const api = {
  health: () => get<{ status: string; mode: string }>('/health'),
  dashboard: () => get<Dashboard>('/dashboard'),
  events: (sev = 'all') => get<{ data: SecurityEvent[]; live: boolean }>(`/events?severity=${sev}`),
  incidents: () => get<{ data: Incident[]; live: boolean }>('/incidents'),
  integrations: () => get<{ data: Integration[]; mode: string }>('/integrations'),
  connectors: () => get<{ data: ConnectorSpec[]; mode: string }>('/connectors'),
  saveConnector: (key: string, body: { enabled?: boolean; fields?: Record<string, string | boolean> }) =>
    post<{ ok: boolean; error?: string }>(`/connectors/${key}`, body),
  enableConnector: (key: string, enabled: boolean) =>
    post<{ ok: boolean }>(`/connectors/${key}/enable`, { enabled }),
  testConnector: (key: string) => post<TestResult>(`/connectors/${key}/test`, {}),
  resetConnector: (key: string) => del<{ ok: boolean }>(`/connectors/${key}`),
  savedHunts: () => get<{ data: { name: string; desc: string; tech: string; hosts: string; hits: string }[] }>('/hunting/saved'),
  runHunt: () => post<{ elapsed: string; scanned: number; hits: { host: string; rdp: string; lsass: string; delta: string; severity: Severity }[] }>('/hunting/run', {}),
  responseActions: () => get<{ data: { time: string; action: string; target: string; incident: string; source: string; status: string }[] }>('/response/actions'),
  runPlaybook: (playbook: string, target?: string) => post<{ started: boolean; ticket: string }>('/response/run', { playbook, target }),
  copilot: (messages: { role: 'user' | 'assistant'; content: string }[]) => post<{ reply: string; live: boolean }>('/copilot', { messages }),

  me: () => get<AuthState>('/auth/me'),
  login: async (email: string, password: string): Promise<{ ok: boolean; user?: AuthUser; error?: string }> => {
    const r = await fetch(`${BASE}/auth/login`, {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }),
    });
    const data = await r.json().catch(() => ({}));
    return { ok: r.ok && Boolean(data.ok), user: data.user, error: data.error };
  },
  logout: () => post<{ ok: boolean }>('/auth/logout', {}),

  users: () => get<{ data: ManagedUser[]; available: boolean }>('/users'),
  createUser: (body: { email: string; name: string; password: string; role: string }) =>
    post<{ ok: boolean; error?: string; user?: ManagedUser }>('/users', body),
  updateUser: (id: string, patch: { role?: string; status?: string }) =>
    fetch(`${BASE}/users/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch) }).then((r) => r.json()),
  deleteUser: (id: string) => del<{ ok: boolean; error?: string }>(`/users/${id}`),
};
