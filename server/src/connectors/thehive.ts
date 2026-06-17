import { effective, isConfigured } from '../services/connectors/runtime.js';
const thcfg = () => effective('thehive');
import { httpClient, logConnectorError } from './http.js';
import type { Incident, IncidentStatus, Severity, HealthState } from '../types.js';

/** TheHive 5 connector — case management / SOAR over /api/v1. */

function client() {
  return httpClient(thcfg().url, thcfg().insecureTLS, {
    headers: {
      Authorization: `Bearer ${thcfg().apiKey}`,
      'Content-Type': 'application/json',
    },
  });
}

function mapSeverity(n: number): Severity {
  return n >= 4 ? 'crit' : n === 3 ? 'high' : n === 2 ? 'med' : 'low';
}
function mapStatus(stage: string): IncidentStatus {
  const s = (stage || '').toLowerCase();
  if (s.includes('new') || s.includes('open')) return 'new';
  if (s.includes('progress') || s.includes('inprogress')) return 'prog';
  if (s.includes('contain')) return 'cont';
  if (s.includes('closed') || s.includes('resolved')) return 'res';
  return 'prog';
}

export async function thehiveHealth(): Promise<HealthState> {
  if (!isConfigured('thehive')) return 'off';
  try {
    const { status } = await client().get('/api/v1/status/public');
    return status === 200 ? 'on' : 'deg';
  } catch (err) {
    logConnectorError('thehive-health', err);
    return 'deg';
  }
}

export async function thehiveCases(limit = 30): Promise<Incident[] | null> {
  if (!isConfigured('thehive')) return null;
  try {
    const { data } = await client().post('/api/v1/query', {
      query: [
        { _name: 'listCase' },
        { _name: 'sort', _fields: [{ _createdAt: 'desc' }] },
        { _name: 'page', from: 0, to: limit },
      ],
    });
    return (data || []).map((c: any): Incident => ({
      id: c.number ? `INC-${c.number}` : c._id,
      title: c.title || 'Caso',
      severity: mapSeverity(Number(c.severity || 2)),
      status: mapStatus(c.stage || c.status),
      assignee: (c.assignee || 'SOC').slice(0, 2).toUpperCase(),
      sla: '—',
      events: Number(c.observableCount || 0),
    }));
  } catch (err) {
    logConnectorError('thehive-cases', err);
    return null;
  }
}

export async function thehiveCreateCase(title: string, description: string, severity = 2): Promise<string | null> {
  if (!isConfigured('thehive')) return null;
  try {
    const { data } = await client().post('/api/v1/case', {
      title, description, severity, tlp: 2, pap: 2,
    });
    return data?.number ? `INC-${data.number}` : data?._id || null;
  } catch (err) {
    logConnectorError('thehive-create', err);
    return null;
  }
}

import type { ProviderFactory } from '../services/connectors/sdk.js';
/** Provedor TheHive — saúde + incidentes/casos. */
export const thehiveProvider: ProviderFactory = () => ({
  key: 'thehive',
  label: 'TheHive',
  capabilities: ['health', 'incidents'],
  health: thehiveHealth,
  incidents: thehiveCases,
});
