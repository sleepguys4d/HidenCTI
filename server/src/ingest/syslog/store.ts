import { config } from '../../config.js';
import type { SecurityEvent } from '../../types.js';
import { parseSyslog, deriveSeverity, type ParsedSyslog } from './parser.js';

/**
 * Armazena em memória os eventos de syslog recebidos das firewalls.
 *
 * É um buffer circular limitado (sem dependência de base de dados) que mantém
 * os eventos mais recentes e estatísticas de ingestão em tempo real. Quando a
 * persistência por tenant entrar (sub-fase 03.5), este módulo passa a escrever
 * também na base de dados — a interface pública mantém-se.
 */

export interface SyslogRecord {
  event: SecurityEvent;
  tenant: string;
  vendor: string;
  proto: string;
  ports: string;
  raw: string;
}

interface Stats {
  total: number;            // total recebido desde o arranque
  blocked: number;          // ações de bloqueio
  bytes: number;
  lastAt: number;           // epoch ms do último pacote
  lastSource: string;       // IP do último emissor
  vendors: Record<string, number>;
  recentTimes: number[];    // epoch ms dos últimos eventos (para estimar EPS)
}

const MAX = Math.max(100, config.syslog.maxEvents);
const buffer: SyslogRecord[] = [];
const stats: Stats = { total: 0, blocked: 0, bytes: 0, lastAt: 0, lastSource: '', vendors: {}, recentTimes: [] };

let seq = 0;

// Mapeamento opcional IP→tenant (full multi-tenant chega em 03.5).
let tenantMap: Record<string, string> = {};
export function setTenantMap(spec: string): void {
  const next: Record<string, string> = {};
  for (const pair of (spec || '').split(',').map((s) => s.trim()).filter(Boolean)) {
    const [ip, slug] = pair.split('=').map((s) => s.trim());
    if (ip && slug) next[ip] = slug;
  }
  tenantMap = next;
}
setTenantMap(config.syslog.tenantMap);

function resolveTenant(remoteIp: string): string {
  return tenantMap[remoteIp] || config.defaultTenant.slug;
}

function hhmmss(d: Date): string {
  return d.toTimeString().slice(0, 8);
}

/** Constrói uma descrição legível a partir dos campos extraídos. */
function describe(p: ParsedSyslog): string {
  const act =
    p.action === 'block' ? 'Connection blocked' : p.action === 'pass' ? 'Connection allowed' : 'Firewall event';
  const seg: string[] = [act];
  if (p.proto) seg.push(p.proto.toUpperCase());
  if (p.iface) seg.push(`if ${p.iface}`);
  if (p.dstPort) seg.push(`→ port ${p.dstPort}`);
  const tail = seg.join(' · ');
  // Anexa um excerto da mensagem bruta quando não há estrutura suficiente.
  if (!p.action && !p.srcIp && p.message) return `Firewall · ${p.message.slice(0, 90)}`;
  return `${p.vendor} · ${tail}`;
}

function toEvent(p: ParsedSyslog): SecurityEvent {
  return {
    id: `FW-${Date.now().toString(36)}-${(seq++).toString(36)}`,
    time: hhmmss(p.timestamp),
    severity: deriveSeverity(p),
    source: p.vendor,
    rule: describe(p),
    technique: p.action === 'block' ? 'T1190' : '—',
    host: p.host,
    srcIp: p.srcIp ? (p.srcPort ? `${p.srcIp}:${p.srcPort}` : p.srcIp) : '—',
    dstIp: p.dstIp ? (p.dstPort ? `${p.dstIp}:${p.dstPort}` : p.dstIp) : '—',
    user: '—',
  };
}

/** Ponto de entrada: ingere uma linha de syslog bruta. */
export function ingest(raw: string, remoteIp: string): SyslogRecord | null {
  const line = raw.trim();
  if (!line) return null;

  const parsed = parseSyslog(line, remoteIp);
  const event = toEvent(parsed);
  const record: SyslogRecord = {
    event,
    tenant: resolveTenant(remoteIp),
    vendor: parsed.vendor,
    proto: parsed.proto,
    ports: [parsed.srcPort, parsed.dstPort].filter(Boolean).join('→'),
    raw: line,
  };

  buffer.unshift(record);
  if (buffer.length > MAX) buffer.length = MAX;

  const now = Date.now();
  stats.total += 1;
  stats.bytes += Buffer.byteLength(line);
  stats.lastAt = now;
  stats.lastSource = remoteIp;
  if (parsed.action === 'block') stats.blocked += 1;
  stats.vendors[parsed.vendor] = (stats.vendors[parsed.vendor] || 0) + 1;
  stats.recentTimes.push(now);
  // Mantém apenas a janela dos últimos 60s para estimar EPS.
  const cutoff = now - 60_000;
  while (stats.recentTimes.length && stats.recentTimes[0] < cutoff) stats.recentTimes.shift();

  return record;
}

/** Eventos recentes (para fundir no stream da consola), opcionalmente por tenant. */
export function recentEvents(tenantSlug?: string, limit = MAX): SecurityEvent[] {
  const src = tenantSlug ? buffer.filter((r) => r.tenant === tenantSlug) : buffer;
  return src.slice(0, limit).map((r) => r.event);
}

/** Estatísticas de ingestão para o painel de Integrações / diagnóstico. */
export function syslogStats() {
  const epsWindow = stats.recentTimes.length;
  return {
    enabled: config.syslog.enabled,
    total: stats.total,
    blocked: stats.blocked,
    buffered: buffer.length,
    bytes: stats.bytes,
    epsLastMinute: epsWindow,
    eps: +(epsWindow / 60).toFixed(2),
    lastAt: stats.lastAt ? new Date(stats.lastAt).toISOString() : null,
    lastSource: stats.lastSource || null,
    vendors: stats.vendors,
  };
}

/** Apenas para a semente de demonstração. */
export function _bufferLength(): number {
  return buffer.length;
}
