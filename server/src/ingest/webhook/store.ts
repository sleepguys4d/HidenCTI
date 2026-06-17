import { config } from '../../config.js';
import type { SecurityEvent, Severity } from '../../types.js';

/**
 * Ingestão por webhook de entrada — a via universal de integração.
 *
 * Qualquer solução externa (um SIEM, um EDR, um WAF, uma automação, uma API de
 * parceiro…) pode enviar eventos por HTTP POST. O normalizador aceita JSON
 * arbitrário e mapeia os nomes de campo mais comuns para o evento da consola,
 * por isso integra-se sem código nem formato fixo.
 */

interface Stats {
  total: number;
  lastAt: number;
  lastSource: string;
  sources: Record<string, number>;
  recentTimes: number[];
}

const MAX = Math.max(100, config.webhook.maxEvents);
const buffer: SecurityEvent[] = [];
const stats: Stats = { total: 0, lastAt: 0, lastSource: '', sources: {}, recentTimes: [] };
let seq = 0;

/** Primeiro valor presente entre várias chaves possíveis. */
function pick(o: Record<string, any>, keys: string[]): string {
  for (const k of keys) {
    if (o[k] !== undefined && o[k] !== null && o[k] !== '') return String(o[k]);
  }
  return '';
}

function toSeverity(v: string): Severity {
  const s = v.toLowerCase().trim();
  if (['crit', 'critical', 'fatal', 'emergency', 'emerg', '5', '10'].includes(s)) return 'crit';
  if (['high', 'error', 'err', 'alert', '4', '8', '9'].includes(s)) return 'high';
  if (['med', 'medium', 'warning', 'warn', '3', '6', '7'].includes(s)) return 'med';
  if (['low', 'notice', '2', '4', '5'].includes(s)) return 'low';
  if (['info', 'information', 'informational', 'debug', '1', '0'].includes(s)) return 'info';
  // Número solto: escala syslog/0-10.
  const n = Number(s);
  if (Number.isFinite(n)) return n >= 9 ? 'crit' : n >= 7 ? 'high' : n >= 5 ? 'med' : n >= 3 ? 'low' : 'info';
  return 'med';
}

function hhmmss(v: string): string {
  if (v) {
    const d = new Date(v);
    if (!isNaN(d.getTime())) return d.toTimeString().slice(0, 8);
    if (/^\d{2}:\d{2}:\d{2}/.test(v)) return v.slice(0, 8);
  }
  return new Date().toTimeString().slice(0, 8);
}

/** Mapeia um objeto JSON arbitrário para um evento da consola. */
export function normalize(payload: Record<string, any>, sourceIp: string): SecurityEvent {
  const o = payload || {};
  const source = pick(o, ['source', 'product', 'vendor', 'tool', 'app', 'integration']) || 'Webhook';
  const rule =
    pick(o, ['rule', 'message', 'title', 'description', 'event', 'name', 'alert', 'signature']) ||
    JSON.stringify(o).slice(0, 90);
  return {
    id: pick(o, ['id', 'uuid', 'event_id', '_id']) || `WH-${Date.now().toString(36)}-${(seq++).toString(36)}`,
    time: hhmmss(pick(o, ['timestamp', 'time', '@timestamp', 'ts', 'date'])),
    severity: toSeverity(pick(o, ['severity', 'level', 'priority', 'risk', 'criticality'])),
    source,
    rule,
    technique: pick(o, ['technique', 'mitre', 'mitre_id', 'tactic']) || '—',
    host: pick(o, ['host', 'hostname', 'device', 'agent', 'asset', 'computer']) || sourceIp,
    srcIp: pick(o, ['src_ip', 'srcIp', 'source_ip', 'sourceAddress', 'src', 'client_ip']) || '—',
    dstIp: pick(o, ['dst_ip', 'dstIp', 'destination_ip', 'destinationAddress', 'dst', 'dest_ip']) || '—',
    user: pick(o, ['user', 'username', 'account', 'user_name', 'subject']) || '—',
  };
}

/** Ingere um evento (ou vários). Devolve o número aceite. */
export function ingest(body: unknown, sourceIp: string): number {
  const items: Record<string, any>[] = Array.isArray(body)
    ? body
    : (body && typeof body === 'object' && Array.isArray((body as any).events))
      ? (body as any).events
      : (body && typeof body === 'object') ? [body as Record<string, any>] : [];
  let n = 0;
  const now = Date.now();
  for (const item of items) {
    if (!item || typeof item !== 'object') continue;
    buffer.unshift(normalize(item, sourceIp));
    if (buffer.length > MAX) buffer.length = MAX;
    n += 1;
  }
  if (n) {
    stats.total += n;
    stats.lastAt = now;
    stats.lastSource = sourceIp;
    stats.sources[sourceIp] = (stats.sources[sourceIp] || 0) + n;
    for (let i = 0; i < n; i++) stats.recentTimes.push(now);
    const cutoff = now - 60_000;
    while (stats.recentTimes.length && stats.recentTimes[0] < cutoff) stats.recentTimes.shift();
  }
  return n;
}

export function recentEvents(limit = MAX): SecurityEvent[] {
  return buffer.slice(0, limit);
}

export function webhookStats() {
  const win = stats.recentTimes.length;
  return {
    enabled: true,
    total: stats.total,
    buffered: buffer.length,
    epsLastMinute: win,
    eps: +(win / 60).toFixed(2),
    lastAt: stats.lastAt ? new Date(stats.lastAt).toISOString() : null,
    lastSource: stats.lastSource || null,
    sources: stats.sources,
  };
}

export function _bufferLength(): number {
  return buffer.length;
}
