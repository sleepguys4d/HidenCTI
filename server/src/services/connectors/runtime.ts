import { config } from '../../config.js';
import { prisma, dbEnabled } from '../../db/client.js';
import { encryptJson, decryptJson, encryptionAvailable } from '../../crypto/secretbox.js';
import { REGISTRY, getSpec, toConnectorType, type ConnectorSpec } from './registry.js';

/**
 * Camada de configuração de conectores em tempo de execução.
 *
 * É a fonte de verdade que os conectores leem (em vez do `.env` estático), e o
 * que a GUI de integrações manipula. Funciona em qualquer modo:
 *   • Com base de dados  → persiste em `ConnectorConfig` (segredos cifrados).
 *   • Sem base de dados  → mantém em memória (semeado a partir do `.env`).
 *
 * Os segredos nunca saem deste módulo em texto simples para a interface.
 */

type Fields = Record<string, string | boolean>;
interface Record_ {
  enabled: boolean;
  fields: Fields;
  source: 'env' | 'db' | 'memory';
}

const SECRET_NAMES = new Map<string, Set<string>>(
  REGISTRY.map((s) => [s.key, new Set(s.fields.filter((f) => f.secret).map((f) => f.name))]),
);

const store = new Map<string, Record_>();

/** Semeia a partir do `.env` (sincronamente, para estar disponível no arranque). */
function seedFromEnv(): void {
  const put = (key: string, enabled: boolean, fields: Fields) =>
    store.set(key, { enabled, fields, source: 'env' });

  const w = config.wazuh;
  put('wazuh', Boolean(w.indexerUrl || w.apiUrl), {
    indexerUrl: w.indexerUrl, indexerUser: w.indexerUser, indexerPassword: w.indexerPassword,
    alertsIndex: w.alertsIndex, apiUrl: w.apiUrl, apiUser: w.apiUser, apiPassword: w.apiPassword,
    insecureTLS: w.insecureTLS,
  });
  put('misp', Boolean(config.misp.url && config.misp.apiKey), {
    url: config.misp.url, apiKey: config.misp.apiKey, insecureTLS: config.misp.insecureTLS,
  });
  put('thehive', Boolean(config.thehive.url && config.thehive.apiKey), {
    url: config.thehive.url, apiKey: config.thehive.apiKey, insecureTLS: config.thehive.insecureTLS,
  });
  put('firewall-syslog', config.syslog.enabled, {
    udpPort: String(config.syslog.udpPort), tcpPort: String(config.syslog.tcpPort), tenantMap: config.syslog.tenantMap,
  });
  put('webhook', Boolean(config.webhook.token), {
    token: config.webhook.token, note: 'POST /api/ingest/webhook',
  });
  // Tipos restantes do registo começam vazios/desligados.
  for (const spec of REGISTRY) {
    if (!store.has(spec.key)) {
      const fields: Fields = {};
      for (const f of spec.fields) if (f.default !== undefined) fields[f.name] = f.default;
      put(spec.key, false, fields);
    }
  }
}
seedFromEnv();

/** Sobrepõe a configuração persistida na base de dados (chamado no arranque). */
export async function initRuntime(): Promise<void> {
  if (!dbEnabled || !encryptionAvailable()) return;
  try {
    const tenant = await prisma().tenant.findUnique({
      where: { slug: config.defaultTenant.slug },
      include: { connectors: true },
    });
    if (!tenant) return;
    const typeToKey = new Map(REGISTRY.map((s) => [toConnectorType(s.key), s.key]));
    for (const c of tenant.connectors) {
      const key = typeToKey.get(c.type);
      if (!key) continue;
      const secrets = c.secretCipher ? decryptJson<Fields>(c.secretCipher) : {};
      const meta = (c.meta as Fields | null) || {};
      const fields: Fields = { ...meta, ...secrets };
      if (c.baseUrl) fields[primaryUrlField(key)] = c.baseUrl;
      store.set(key, { enabled: c.enabled, fields, source: 'db' });
    }
  } catch {
    /* mantém o estado semeado do .env */
  }
}

function primaryUrlField(key: string): string {
  const spec = getSpec(key);
  const urlF = spec?.fields.find((f) => f.type === 'url');
  return urlF?.name || 'url';
}

// ── Leitura (para os conectores) ──

/** Configuração efetiva de um conector (valores em claro, uso interno). */
export function effective(key: string): Record<string, any> {
  return { ...(store.get(key)?.fields || {}) };
}

export function isEnabled(key: string): boolean {
  return Boolean(store.get(key)?.enabled);
}

export function isConfigured(key: string): boolean {
  const spec = getSpec(key);
  if (!spec) return false;
  const f = store.get(key)?.fields || {};
  return spec.requiredFor.every((name) => Boolean(f[name]));
}

/** Um conector é consultado ao vivo quando: não estamos em DEMO global,
 *  está ativado na GUI e tem os campos obrigatórios preenchidos. */
export function isLive(key: string): boolean {
  return !config.demoMode && isEnabled(key) && isConfigured(key);
}

// ── Escrita (para a GUI) ──

/** Lista para a interface (segredos mascarados). */
export function listForUi() {
  return REGISTRY.map((spec) => {
    const rec = store.get(spec.key)!;
    const secrets = SECRET_NAMES.get(spec.key)!;
    return {
      key: spec.key,
      label: spec.label,
      category: spec.category,
      push: Boolean(spec.push),
      pull: Boolean(spec.pull),
      testable: spec.testable,
      enabled: rec.enabled,
      configured: isConfigured(spec.key),
      source: rec.source,
      fields: spec.fields.map((f) => ({
        name: f.name, label: f.label, type: f.type, required: Boolean(f.required),
        secret: Boolean(f.secret), placeholder: f.placeholder, help: f.help,
        // Segredos: nunca devolvemos o valor, só se está definido.
        value: f.secret ? '' : (rec.fields[f.name] ?? f.default ?? ''),
        isSet: f.secret ? Boolean(rec.fields[f.name]) : undefined,
      })),
    };
  });
}

async function persist(key: string, rec: Record_): Promise<void> {
  if (!dbEnabled || !encryptionAvailable()) { rec.source = 'memory'; return; }
  try {
    const tenant = await prisma().tenant.findUnique({ where: { slug: config.defaultTenant.slug } });
    if (!tenant) { rec.source = 'memory'; return; }
    const secrets: Fields = {};
    const meta: Fields = {};
    const spec = getSpec(key)!;
    const secretSet = SECRET_NAMES.get(key)!;
    for (const [k, v] of Object.entries(rec.fields)) {
      if (secretSet.has(k)) secrets[k] = v;
      else meta[k] = v;
    }
    const type = toConnectorType(key) as any;
    await prisma().connectorConfig.upsert({
      where: { tenantId_type: { tenantId: tenant.id, type } },
      update: {
        enabled: rec.enabled, name: spec.label,
        baseUrl: String(rec.fields[primaryUrlField(key)] || '') || null,
        secretCipher: Object.keys(secrets).length ? encryptJson(secrets) : null,
        meta: meta as any,
      },
      create: {
        tenantId: tenant.id, type, name: spec.label,
        baseUrl: String(rec.fields[primaryUrlField(key)] || '') || null,
        secretCipher: Object.keys(secrets).length ? encryptJson(secrets) : null,
        meta: meta as any, enabled: rec.enabled,
      },
    });
    rec.source = 'db';
  } catch {
    rec.source = 'memory';
  }
}

/** Cria/atualiza a configuração de um conector a partir da GUI. */
export async function upsert(
  key: string,
  patch: { enabled?: boolean; fields?: Fields },
): Promise<{ ok: boolean; error?: string }> {
  const spec = getSpec(key);
  if (!spec) return { ok: false, error: 'tipo desconhecido' };
  const rec = store.get(key)!;
  const secretSet = SECRET_NAMES.get(key)!;

  if (patch.fields) {
    for (const [k, v] of Object.entries(patch.fields)) {
      // Segredo enviado vazio = manter o existente (a GUI não recebe o valor).
      if (secretSet.has(k) && (v === '' || v === undefined)) continue;
      rec.fields[k] = v;
    }
  }
  if (typeof patch.enabled === 'boolean') rec.enabled = patch.enabled;

  await persist(key, rec);
  applySideEffects(key, rec);
  return { ok: true };
}

export async function setEnabled(key: string, enabled: boolean): Promise<{ ok: boolean }> {
  const rec = store.get(key);
  if (!rec) return { ok: false };
  rec.enabled = enabled;
  await persist(key, rec);
  applySideEffects(key, rec);
  return { ok: true };
}

export async function remove(key: string): Promise<void> {
  // "Remover" repõe para o estado semeado do .env e apaga da BD.
  if (dbEnabled && encryptionAvailable()) {
    try {
      const tenant = await prisma().tenant.findUnique({ where: { slug: config.defaultTenant.slug } });
      if (tenant) await prisma().connectorConfig.deleteMany({ where: { tenantId: tenant.id, type: toConnectorType(key) as any } });
    } catch { /* ignora */ }
  }
  store.delete(key);
  seedSingleFromEnv(key);
}

function seedSingleFromEnv(key: string): void {
  // Repõe um único conector a partir do .env / valores por defeito.
  const spec = getSpec(key);
  if (!spec) return;
  const fields: Fields = {};
  for (const f of spec.fields) if (f.default !== undefined) fields[f.name] = f.default;
  store.set(key, { enabled: false, fields, source: 'env' });
}

/** Efeitos colaterais de certas integrações (ex.: ligar/desligar o syslog). */
type SideEffectHook = (enabled: boolean, fields: Fields) => void;
const sideEffects = new Map<string, SideEffectHook>();
export function registerSideEffect(key: string, hook: SideEffectHook): void {
  sideEffects.set(key, hook);
}
function applySideEffects(key: string, rec: Record_): void {
  const hook = sideEffects.get(key);
  if (hook) { try { hook(rec.enabled, rec.fields); } catch { /* best-effort */ } }
}
