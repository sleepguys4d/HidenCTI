import { effective, isConfigured } from '../services/connectors/runtime.js';
const wzcfg = () => effective('wazuh');
import { httpClient, logConnectorError } from './http.js';
import type { SecurityEvent, Severity, HealthState } from '../types.js';

/**
 * Wazuh connector.
 * - Manager API (default :55000) for health + agent inventory. Requires a JWT
 *   obtained from /security/user/authenticate (HTTP basic).
 * - Wazuh Indexer / OpenSearch (default :9200) for alert search on
 *   wazuh-alerts-* indices.
 */

let cachedToken: { value: string; expires: number } | null = null;

async function getToken(): Promise<string | null> {
  if (!wzcfg().apiUrl) return null;
  if (cachedToken && cachedToken.expires > Date.now()) return cachedToken.value;
  try {
    const client = httpClient(wzcfg().apiUrl, wzcfg().insecureTLS, {
      auth: { username: wzcfg().apiUser, password: wzcfg().apiPassword },
    });
    const { data } = await client.get('/security/user/authenticate?raw=true');
    const token = typeof data === 'string' ? data : data?.data?.token;
    if (!token) return null;
    cachedToken = { value: token, expires: Date.now() + 13 * 60 * 1000 }; // ~15min TTL
    return token;
  } catch (err) {
    logConnectorError('wazuh-auth', err);
    return null;
  }
}

function levelToSeverity(level: number): Severity {
  if (level >= 13) return 'crit';
  if (level >= 10) return 'high';
  if (level >= 7) return 'med';
  if (level >= 4) return 'low';
  return 'info';
}

export async function wazuhHealth(): Promise<HealthState> {
  if (!isConfigured('wazuh')) return 'off';
  const token = await getToken();
  if (!wzcfg().apiUrl) return wzcfg().indexerUrl ? 'on' : 'off';
  if (!token) return 'deg';
  try {
    const client = httpClient(wzcfg().apiUrl, wzcfg().insecureTLS, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const { data } = await client.get('/manager/status');
    const services = Object.values(data?.data?.affected_items?.[0] || {});
    const running = services.filter((s) => s === 'running').length;
    return running === 0 ? 'off' : running < services.length ? 'deg' : 'on';
  } catch (err) {
    logConnectorError('wazuh-health', err);
    return 'deg';
  }
}

export async function wazuhAlerts(limit = 50): Promise<SecurityEvent[] | null> {
  if (!wzcfg().indexerUrl) return null;
  try {
    const client = httpClient(wzcfg().indexerUrl, wzcfg().insecureTLS, {
      auth: { username: wzcfg().indexerUser, password: wzcfg().indexerPassword },
      headers: { 'Content-Type': 'application/json' },
    });
    const body = {
      size: limit,
      sort: [{ timestamp: { order: 'desc' } }],
      query: { range: { timestamp: { gte: 'now-24h' } } },
    };
    const { data } = await client.post(`/${wzcfg().alertsIndex}/_search`, body);
    const hits = data?.hits?.hits || [];
    return hits.map((h: any, i: number): SecurityEvent => {
      const s = h._source || {};
      const time = (s.timestamp || '').slice(11, 19) || '—';
      return {
        id: h._id || `WZ-${i}`,
        time,
        severity: levelToSeverity(Number(s.rule?.level || 0)),
        source: 'Wazuh',
        rule: s.rule?.description || 'Alerta Wazuh',
        technique: (s.rule?.mitre?.id || [])[0] || '—',
        host: s.agent?.name || '—',
        srcIp: s.data?.srcip || '—',
        dstIp: s.data?.dstip || '—',
        user: s.data?.srcuser || s.data?.dstuser || '—',
      };
    });
  } catch (err) {
    logConnectorError('wazuh-alerts', err);
    return null;
  }
}

export async function wazuhAgents(): Promise<{ total: number; active: number } | null> {
  const token = await getToken();
  if (!token || !wzcfg().apiUrl) return null;
  try {
    const client = httpClient(wzcfg().apiUrl, wzcfg().insecureTLS, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const { data } = await client.get('/agents/summary/status');
    const items = data?.data?.affected_items?.[0] || data?.data || {};
    return { total: Number(items.total || 0), active: Number(items.active || 0) };
  } catch (err) {
    logConnectorError('wazuh-agents', err);
    return null;
  }
}

import type { ProviderFactory } from '../services/connectors/sdk.js';
/** Provedor Wazuh — saúde + eventos para o stream unificado. */
export const wazuhProvider: ProviderFactory = () => ({
  key: 'wazuh',
  label: 'Wazuh',
  capabilities: ['health', 'events'],
  health: wazuhHealth,
  events: wazuhAlerts,
});
