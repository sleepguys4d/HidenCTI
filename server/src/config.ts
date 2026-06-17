import 'dotenv/config';

const bool = (v: string | undefined, def = false): boolean =>
  v === undefined ? def : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());

const int = (v: string | undefined, def: number): number => {
  const n = parseInt(v ?? '', 10);
  return Number.isFinite(n) ? n : def;
};

export const config = {
  port: parseInt(process.env.PORT || '4000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  // Atrás de um reverse proxy (TLS), permite obter o IP real do cliente e
  // tratar corretamente os cookies Secure. Em produção confia no 1º salto.
  trustProxy: ((): boolean | number | string => {
    const v = process.env.TRUST_PROXY;
    if (v === undefined) return process.env.NODE_ENV === 'production' ? 1 : false;
    if (v === 'true') return true;
    if (v === 'false') return false;
    const n = Number(v);
    return Number.isFinite(n) ? n : v;
  })(),
  // Content-Security-Policy (ligado por defeito; CSP_DISABLED=true para desligar).
  cspEnabled: !bool(process.env.CSP_DISABLED, false),
  // When DEMO_MODE is on (or a connector is not configured) the API serves
  // realistic simulated data so the platform is usable out-of-the-box.
  demoMode: bool(process.env.DEMO_MODE, true),
  corsOrigin: process.env.CORS_ORIGIN || '*',

  wazuh: {
    // Wazuh manager API (agents / manager health)
    apiUrl: process.env.WAZUH_API_URL || '',          // e.g. https://wazuh.local:55000
    apiUser: process.env.WAZUH_API_USER || '',
    apiPassword: process.env.WAZUH_API_PASSWORD || '',
    // Wazuh indexer (OpenSearch) for alerts
    indexerUrl: process.env.WAZUH_INDEXER_URL || '',   // e.g. https://wazuh.local:9200
    indexerUser: process.env.WAZUH_INDEXER_USER || '',
    indexerPassword: process.env.WAZUH_INDEXER_PASSWORD || '',
    alertsIndex: process.env.WAZUH_ALERTS_INDEX || 'wazuh-alerts-*',
    insecureTLS: bool(process.env.WAZUH_INSECURE_TLS, true),
  },
  misp: {
    url: process.env.MISP_URL || '',                   // e.g. https://misp.local
    apiKey: process.env.MISP_API_KEY || '',
    insecureTLS: bool(process.env.MISP_INSECURE_TLS, true),
  },
  thehive: {
    url: process.env.THEHIVE_URL || '',                // e.g. http://thehive.local:9000
    apiKey: process.env.THEHIVE_API_KEY || '',
    insecureTLS: bool(process.env.THEHIVE_INSECURE_TLS, true),
  },
  anthropic: {
    apiKey: process.env.ANTHROPIC_API_KEY || '',
    model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6',
  },

  // ── Webhook de entrada (push genérico) ──
  // Qualquer solução externa pode enviar eventos por HTTP POST para
  // /api/ingest/webhook, autenticando com um token. É a via universal de
  // integração sem código.
  webhook: {
    token: process.env.WEBHOOK_TOKEN || '',
    maxEvents: int(process.env.WEBHOOK_MAX_EVENTS, 2000),
  },

  // ── Ingestão de syslog das firewalls (push) ──
  // As firewalls (OPNsense, pfSense, FortiGate, Palo Alto, Cisco ASA…) enviam
  // logs por syslog para esta aplicação. O recetor escuta em UDP/TCP, faz o
  // parse do formato e normaliza para eventos da consola.
  syslog: {
    enabled: bool(process.env.SYSLOG_ENABLED, false),
    udp: bool(process.env.SYSLOG_UDP, true),
    tcp: bool(process.env.SYSLOG_TCP, true),
    // 5514 por defeito (não exige privilégios root). Mapeie 514→5514 no host.
    udpPort: int(process.env.SYSLOG_UDP_PORT, 5514),
    tcpPort: int(process.env.SYSLOG_TCP_PORT, 5514),
    bind: process.env.SYSLOG_BIND || '0.0.0.0',
    // Nº máximo de eventos mantidos em memória (buffer circular).
    maxEvents: int(process.env.SYSLOG_MAX_EVENTS, 2000),
    // Mapeamento opcional IP→tenant: "10.0.0.1=cliente-a,10.0.0.2=cliente-b".
    tenantMap: process.env.SYSLOG_TENANT_MAP || '',
  },

  // ── Fase 03 · fundação ──
  database: {
    url: process.env.DATABASE_URL || '',
  },
  security: {
    encryptionKey: process.env.APP_ENCRYPTION_KEY || '',
  },
  defaultTenant: {
    slug: process.env.DEFAULT_TENANT_SLUG || 'sec4data',
    name: process.env.DEFAULT_TENANT_NAME || 'Sec4data',
  },
  admin: {
    email: process.env.ADMIN_EMAIL || 'admin@sec4data.com',
    name: process.env.ADMIN_NAME || 'Administrador',
    // Empty by default: the seed only creates the admin when a password is set.
    password: process.env.ADMIN_PASSWORD || '',
  },

  // ── Autenticação e sessões (Fase 03.2) ──
  auth: {
    // Cookies seguros (Secure) — ative em produção atrás de TLS, ou defina COOKIE_SECURE=true.
    secureCookies: bool(process.env.COOKIE_SECURE, process.env.NODE_ENV === 'production'),
    // Duração da sessão em horas.
    sessionTtlHours: int(process.env.SESSION_TTL_HOURS, 12),
    // Forçar login mesmo sem admin/BD (ex.: para um teste de produção). Normalmente automático.
    force: bool(process.env.AUTH_REQUIRED, false),
  },
};

/** True when a database is configured (Phase 03 features available). */
export const dbEnabled = Boolean(config.database.url);

export const connectorConfigured = {
  wazuh: () => Boolean(config.wazuh.indexerUrl || config.wazuh.apiUrl),
  misp: () => Boolean(config.misp.url && config.misp.apiKey),
  thehive: () => Boolean(config.thehive.url && config.thehive.apiKey),
  anthropic: () => Boolean(config.anthropic.apiKey),
};

export const useReal = (c: keyof typeof connectorConfigured): boolean =>
  !config.demoMode && connectorConfigured[c]();
