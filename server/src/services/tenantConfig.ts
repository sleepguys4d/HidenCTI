import { prisma, dbEnabled } from '../db/client.js';
import { decryptJson, encryptionAvailable } from '../crypto/secretbox.js';
import { config } from '../config.js';

/**
 * Resolves the connector configuration for a tenant. Prefers per-tenant config
 * stored (encrypted) in the database; falls back to the global .env config when
 * the DB is unavailable or empty. This is the bridge that lets the platform move
 * from a single global .env to per-tenant connectors (full wiring lands in 03.5).
 */

export interface WazuhCreds {
  apiUrl?: string; apiUser?: string; apiPassword?: string;
  indexerUrl?: string; indexerUser?: string; indexerPassword?: string;
  alertsIndex?: string; insecureTLS?: boolean;
}
export interface MispCreds { url?: string; apiKey?: string; insecureTLS?: boolean }
export interface TheHiveCreds { url?: string; apiKey?: string; insecureTLS?: boolean }

export interface ResolvedConnectors {
  source: 'db' | 'env';
  wazuh?: WazuhCreds;
  misp?: MispCreds;
  thehive?: TheHiveCreds;
}

function fromEnv(): ResolvedConnectors {
  return {
    source: 'env',
    wazuh: { ...config.wazuh },
    misp: { ...config.misp },
    thehive: { ...config.thehive },
  };
}

export async function resolveConnectors(
  tenantSlug: string = config.defaultTenant.slug,
): Promise<ResolvedConnectors> {
  if (!dbEnabled || !encryptionAvailable()) return fromEnv();

  try {
    const tenant = await prisma().tenant.findUnique({
      where: { slug: tenantSlug },
      include: { connectors: true },
    });
    if (!tenant || tenant.connectors.length === 0) return fromEnv();

    const out: ResolvedConnectors = { source: 'db' };
    for (const c of tenant.connectors) {
      if (!c.enabled || !c.secretCipher) continue;
      const creds = decryptJson<Record<string, unknown>>(c.secretCipher);
      const base = c.baseUrl ? { url: c.baseUrl } : {};
      if (c.type === 'WAZUH') out.wazuh = { ...(creds as WazuhCreds) };
      else if (c.type === 'MISP') out.misp = { ...base, ...(creds as MispCreds) };
      else if (c.type === 'THEHIVE') out.thehive = { ...base, ...(creds as TheHiveCreds) };
    }
    // If the DB had a tenant but no usable connectors, prefer env.
    if (!out.wazuh && !out.misp && !out.thehive) return fromEnv();
    return out;
  } catch {
    return fromEnv();
  }
}
