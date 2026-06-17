import { httpClient, logConnectorError } from '../../connectors/http.js';
import { wazuhHealth } from '../../connectors/wazuh.js';
import { mispHealth } from '../../connectors/misp.js';
import { thehiveHealth } from '../../connectors/thehive.js';
import { syslogStats } from '../../ingest/syslog/index.js';
import { webhookStats } from '../../ingest/webhook/index.js';
import { effective, isConfigured } from './runtime.js';
import type { HealthState } from '../../types.js';

/**
 * Teste de ligação de um conector, a partir da configuração atualmente guardada.
 * Funciona em qualquer modo (até em DEMO) porque faz uma sondagem real ao alvo.
 */

export interface TestResult {
  ok: boolean;
  state: HealthState;
  message: string;
}

const fromHealth = (s: HealthState): TestResult => ({
  ok: s === 'on',
  state: s,
  message: s === 'on' ? 'Connected — target responding.' : s === 'deg' ? 'Reachable, but with a warning (authentication or partial service).' : 'No response — check URL and credentials.',
});

/** Sondagem genérica: o alvo é alcançável se responder com qualquer HTTP. */
async function probeUrl(url: string, insecure: boolean): Promise<TestResult> {
  if (!url) return { ok: false, state: 'off', message: 'URL not set.' };
  try {
    const res = await httpClient(url, insecure, { timeout: 6000 }).get('/', { validateStatus: () => true });
    return { ok: true, state: 'on', message: `Reachable (HTTP ${res.status}).` };
  } catch (err) {
    logConnectorError('probe', err);
    return { ok: false, state: 'off', message: 'Unreachable — check URL, network and TLS.' };
  }
}

export async function testConnector(key: string): Promise<TestResult> {
  if (key === 'firewall-syslog') {
    const s = syslogStats();
    if (!s.enabled) return { ok: false, state: 'off', message: 'Syslog receiver disabled. Enable it to start receiving.' };
    return { ok: true, state: 'on', message: `Receiver active · ${s.total} events received · ${s.epsLastMinute}/min.` };
  }

  if (key === 'webhook') {
    const f = effective('webhook');
    if (!isConfigured('webhook')) return { ok: false, state: 'off', message: 'Set an ingestion token to enable the webhook.' };
    const s = webhookStats();
    return { ok: true, state: 'on', message: `Ready to receive at POST /api/ingest/webhook (X-SOCX-Token) · ${s.total} events received.` };
  }

  if (!isConfigured(key)) {
    return { ok: false, state: 'off', message: 'Fill in the required fields before testing.' };
  }

  if (key === 'wazuh') return fromHealth(await wazuhHealth());
  if (key === 'misp') return fromHealth(await mispHealth());
  if (key === 'thehive') return fromHealth(await thehiveHealth());

  // Tipos genéricos (OPNsense e restantes): alcançabilidade HTTP.
  const f = effective(key);
  return probeUrl(String(f.url || ''), Boolean(f.insecureTLS));
}
