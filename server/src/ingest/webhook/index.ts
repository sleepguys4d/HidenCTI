import { config } from '../../config.js';
import { ingest, _bufferLength } from './store.js';

/**
 * Em modo DEMO, injeta alguns eventos de webhook de exemplo (com formatos de
 * campo diferentes) para a via de integração ser visível sem um emissor real.
 */
const DEMO: Record<string, unknown>[] = [
  { source: 'CrowdStrike', severity: 'high', title: 'Suspicious behavior detected', host: 'FIN-WS-022', src_ip: '45.137.21.8', technique: 'T1059', user: 'a.cassoma' },
  { product: 'Cloudflare WAF', level: 'critical', message: 'SQL injection blocked', client_ip: '185.220.101.34', dst_ip: '10.20.4.30', rule: 'OWASP-942100' },
  { vendor: 'Microsoft 365', priority: 'medium', description: 'Sign-in from an unusual location', username: 'j.matamba', source_ip: '102.140.5.2' },
];

export function seedWebhookDemo(): void {
  if (!config.demoMode) return;
  if (_bufferLength() > 0) return;
  for (const e of DEMO) ingest(e, '203.0.113.10');
}

export { ingest as ingestWebhook, recentEvents as webhookRecentEvents, webhookStats } from './store.js';
