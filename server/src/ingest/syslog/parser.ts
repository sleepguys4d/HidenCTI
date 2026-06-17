import type { Severity } from '../../types.js';

/**
 * Parser de syslog para logs de firewall.
 *
 * Suporta o enquadramento RFC 3164 (BSD) e RFC 5424, e depois faz best-effort
 * para extrair campos estruturados dos formatos de firewall mais comuns em
 * Angola e no mundo: OPNsense / pfSense (filterlog CSV), FortiGate (key=value),
 * Cisco ASA (%ASA-…) e Palo Alto / genérico (CSV / regex).
 *
 * O objetivo não é um parser perfeito de cada fornecedor, mas extrair de forma
 * fiável o essencial — ação, IP origem/destino, portas, protocolo — para
 * alimentar a consola. O texto bruto é sempre preservado.
 */

export interface ParsedSyslog {
  raw: string;
  remoteIp: string;
  facility: number;
  severityNum: number;       // 0 (emerg) … 7 (debug)
  timestamp: Date;
  host: string;
  app: string;               // tag / app-name (ex.: "filterlog")
  message: string;           // corpo após o cabeçalho
  vendor: string;            // OPNsense, pfSense, FortiGate, Cisco ASA, Firewall
  action: string;            // block / pass / deny / allow / drop / —
  srcIp: string;
  dstIp: string;
  srcPort: string;
  dstPort: string;
  proto: string;
  iface: string;
}

const SEVERITY_WORD = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'];

const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const BLOCK_WORDS = ['block', 'blocked', 'deny', 'denied', 'drop', 'dropped', 'reject', 'rejected'];
const PASS_WORDS = ['pass', 'allow', 'allowed', 'permit', 'permitted', 'accept', 'accepted'];

function decodePri(pri: number): { facility: number; severityNum: number } {
  return { facility: Math.floor(pri / 8), severityNum: pri % 8 };
}

/** Normaliza uma ação textual para um vocabulário pequeno e estável. */
function normalizeAction(token: string): string {
  const t = token.toLowerCase();
  if (BLOCK_WORDS.some((w) => t.includes(w))) return 'block';
  if (PASS_WORDS.some((w) => t.includes(w))) return 'pass';
  return '';
}

/** Extrai pares key=value (FortiGate e afins) preservando valores entre aspas. */
function kv(message: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /(\w[\w.-]*)=("([^"]*)"|\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(message))) out[m[1].toLowerCase()] = m[3] ?? m[2];
  return out;
}

/** Reconhece o fornecedor pela tag/mensagem. */
function detectVendor(app: string, message: string): string {
  const a = app.toLowerCase();
  const m = message.toLowerCase();
  if (a.includes('filterlog') || m.startsWith('filterlog')) return m.includes('pf') ? 'pfSense' : 'OPNsense';
  if (m.includes('devname=') || m.includes('fortigate') || /\bfgt\b/.test(m)) return 'FortiGate';
  if (/%asa-/i.test(message) || a.includes('asa')) return 'Cisco ASA';
  if (a.includes('paloalto') || /,TRAFFIC,|,THREAT,/.test(message)) return 'Palo Alto';
  return 'Firewall';
}

/** pfSense / OPNsense filterlog: CSV posicional, com pequenas variações. */
function parseFilterlog(csv: string): Partial<ParsedSyslog> {
  const f = csv.split(',');
  // Layout comum: 0 rulenr,1 subrule,2 anchor,3 tracker,4 interface,5 reason,
  // 6 action,7 direction,8 ipversion, … src,dst e (para tcp/udp) srcport,dstport.
  const action = normalizeAction(f[6] || '') || (f[6] || '').toLowerCase();
  const iface = f[4] || '';
  const protoTok = f.find((x) => /^(tcp|udp|icmp|igmp|esp|gre)$/i.test(x)) || '';
  // Localiza o primeiro IPv4: src = esse, dst = seguinte, e portas logo a seguir.
  const ipIdx = f.findIndex((t) => /^(?:\d{1,3}\.){3}\d{1,3}$/.test(t));
  let srcIp = '', dstIp = '', srcPort = '', dstPort = '';
  if (ipIdx >= 0) {
    srcIp = f[ipIdx] || '';
    dstIp = f[ipIdx + 1] || '';
    if (/^\d{1,5}$/.test(f[ipIdx + 2] || '')) srcPort = f[ipIdx + 2];
    if (/^\d{1,5}$/.test(f[ipIdx + 3] || '')) dstPort = f[ipIdx + 3];
  }
  return { action: normalizeAction(action) || action, iface, srcIp, dstIp, srcPort, dstPort, proto: protoTok.toLowerCase() };
}

/** FortiGate: pares key=value. */
function parseForti(message: string): Partial<ParsedSyslog> {
  const p = kv(message);
  return {
    action: normalizeAction(p['action'] || '') || (p['action'] || ''),
    srcIp: p['srcip'] || '',
    dstIp: p['dstip'] || '',
    srcPort: p['srcport'] || '',
    dstPort: p['dstport'] || '',
    proto: (p['proto'] && /^\d+$/.test(p['proto']) ? protoFromNum(p['proto']) : p['service'] || p['proto'] || '').toLowerCase(),
    iface: p['srcintf'] || p['devname'] || '',
  };
}

function protoFromNum(n: string): string {
  return ({ '1': 'icmp', '6': 'tcp', '17': 'udp', '47': 'gre', '50': 'esp' } as Record<string, string>)[n] || n;
}

/** Cisco ASA: "%ASA-4-106023: Deny tcp src outside:1.2.3.4/53 dst inside:5.6.7.8/80 …" */
function parseAsa(message: string): Partial<ParsedSyslog> {
  const action =
    /\bdeny|denied|drop\b/i.test(message) ? 'block' : /\bbuilt|permit|allow\b/i.test(message) ? 'pass' : '';
  const ipPort = [...message.matchAll(/(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,5})/g)];
  const proto = (message.match(/\b(tcp|udp|icmp)\b/i)?.[1] || '').toLowerCase();
  return {
    action,
    proto,
    srcIp: ipPort[0]?.[1] || '',
    srcPort: ipPort[0]?.[2] || '',
    dstIp: ipPort[1]?.[1] || '',
    dstPort: ipPort[1]?.[2] || '',
  };
}

/** Fallback genérico: extrai IPs e ação por regex. */
function parseGeneric(message: string): Partial<ParsedSyslog> {
  const ips = message.match(IPV4) || [];
  const lower = message.toLowerCase();
  const action = BLOCK_WORDS.some((w) => lower.includes(w))
    ? 'block'
    : PASS_WORDS.some((w) => lower.includes(w))
      ? 'pass'
      : '';
  const proto = (message.match(/\b(tcp|udp|icmp|igmp|esp|gre)\b/i)?.[1] || '').toLowerCase();
  return { action, proto, srcIp: ips[0] || '', dstIp: ips[1] || '' };
}

export function parseSyslog(raw: string, remoteIp: string): ParsedSyslog {
  let rest = raw.trim();
  let pri = 13; // default: facility user(1), severity notice(5)

  const priMatch = rest.match(/^<(\d{1,3})>/);
  if (priMatch) {
    pri = parseInt(priMatch[1], 10);
    rest = rest.slice(priMatch[0].length);
  }
  const { facility, severityNum } = decodePri(pri);

  let host = '';
  let app = '';
  let message = rest;
  let timestamp = new Date();

  // RFC 5424: "1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG"
  const v5 = rest.match(/^1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[[^\]]*\]|-)\s*(.*)$/s);
  if (v5) {
    const t = new Date(v5[1]);
    if (!isNaN(t.getTime())) timestamp = t;
    host = v5[2] === '-' ? '' : v5[2];
    app = v5[3] === '-' ? '' : v5[3];
    message = v5[6] || '';
  } else {
    // RFC 3164: "Mmm dd HH:MM:SS host tag: message"
    const v3 = rest.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\s]+):?\s*(.*)$/s);
    if (v3) {
      const t = new Date(`${v3[1]} ${new Date().getFullYear()}`);
      if (!isNaN(t.getTime())) timestamp = t;
      host = v3[2];
      app = v3[3].replace(/\[\d+\]$/, '');
      message = v3[4] || '';
    } else {
      // Emissor minimalista: "tag[pid]: message" sem timestamp/host.
      const bare = rest.match(/^([A-Za-z][\w-]*)(?:\[\d+\])?:\s*(.*)$/s);
      if (bare) {
        app = bare[1];
        message = bare[2] || '';
      }
    }
  }

  const vendor = detectVendor(app, message);
  let fields: Partial<ParsedSyslog> = {};
  if (vendor === 'OPNsense' || vendor === 'pfSense') fields = parseFilterlog(message);
  else if (vendor === 'FortiGate') fields = parseForti(message);
  else if (vendor === 'Cisco ASA') fields = parseAsa(message);
  else fields = parseGeneric(message);

  return {
    raw,
    remoteIp,
    facility,
    severityNum,
    timestamp,
    host: host || remoteIp,
    app,
    message,
    vendor,
    action: fields.action || '',
    srcIp: fields.srcIp || '',
    dstIp: fields.dstIp || '',
    srcPort: fields.srcPort || '',
    dstPort: fields.dstPort || '',
    proto: fields.proto || '',
    iface: fields.iface || '',
  };
}

/** Converte a severidade do syslog + a ação num nível da consola. */
export function deriveSeverity(p: ParsedSyslog): Severity {
  // Severidade do protocolo syslog tem prioridade quando é elevada.
  if (p.severityNum <= 2) return 'crit';            // emerg / alert / crit
  if (p.severityNum === 3) return 'high';           // err
  // Caso contrário, a ação da firewall guia o nível.
  if (p.action === 'block') {
    const external = isPublic(p.srcIp) || isPublic(p.dstIp);
    return external ? 'high' : 'med';
  }
  if (p.severityNum === 4) return 'med';            // warning
  return p.action === 'pass' ? 'low' : 'info';
}

function isPublic(ip: string): boolean {
  if (!ip) return false;
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some((n) => isNaN(n))) return false;
  if (o[0] === 10) return false;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;
  if (o[0] === 192 && o[1] === 168) return false;
  if (o[0] === 127) return false;
  return true;
}

export { SEVERITY_WORD };
