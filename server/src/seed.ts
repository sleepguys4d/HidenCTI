import 'dotenv/config';
import { hash } from '@node-rs/argon2';
import { prisma, dbEnabled, disconnect } from './db/client.js';
import { encryptJson, encryptionAvailable } from './crypto/secretbox.js';
import { config, connectorConfigured } from './config.js';

/** Connector types this seed migrates. Assignable to Prisma's generated enum. */
type ConnType = 'WAZUH' | 'MISP' | 'THEHIVE';

/**
 * Idempotent foundation seed (sub-fase 03.1).
 *  1. Creates the default tenant (from .env / defaults).
 *  2. Creates the admin user + OWNER membership (only if ADMIN_PASSWORD is set).
 *  3. Migrates the connectors configured in .env into per-tenant ConnectorConfig
 *     rows, with credentials encrypted at rest.
 * Safe to run repeatedly: everything uses upsert.
 */

async function main(): Promise<void> {
  if (!dbEnabled) {
    console.log('[seed] DATABASE_URL ausente — nada a semear (modo legado).');
    return;
  }
  if (!encryptionAvailable()) {
    console.log('[seed] APP_ENCRYPTION_KEY ausente — defina-a para cifrar credenciais. A abortar.');
    process.exitCode = 1;
    return;
  }

  const db = prisma();

  // 1 · Tenant por defeito
  const tenant = await db.tenant.upsert({
    where: { slug: config.defaultTenant.slug },
    update: { name: config.defaultTenant.name },
    create: { slug: config.defaultTenant.slug, name: config.defaultTenant.name, plan: 'owner' },
  });
  console.log(`[seed] tenant: ${tenant.name} (${tenant.slug})`);

  // 2 · Administrador (apenas se houver palavra-passe)
  if (config.admin.password) {
    const passwordHash = await hash(config.admin.password);
    const user = await db.user.upsert({
      where: { email: config.admin.email },
      update: { name: config.admin.name },
      create: { email: config.admin.email, name: config.admin.name, passwordHash, status: 'ACTIVE' },
    });
    await db.membership.upsert({
      where: { userId_tenantId: { userId: user.id, tenantId: tenant.id } },
      update: { role: 'OWNER', status: 'ACTIVE' },
      create: { userId: user.id, tenantId: tenant.id, role: 'OWNER', status: 'ACTIVE' },
    });
    await db.userPreference.upsert({
      where: { userId_tenantId: { userId: user.id, tenantId: tenant.id } },
      update: {},
      create: { userId: user.id, tenantId: tenant.id },
    });
    console.log(`[seed] admin: ${user.email} (OWNER)`);
  } else {
    console.log('[seed] ADMIN_PASSWORD ausente — admin não criado (criar mais tarde por convite).');
  }

  // 3 · Conectores do .env → ConnectorConfig (credenciais cifradas)
  const upsertConnector = async (
    type: ConnType,
    name: string,
    baseUrl: string | undefined,
    creds: Record<string, unknown>,
  ) => {
    await db.connectorConfig.upsert({
      where: { tenantId_type: { tenantId: tenant.id, type } },
      update: { baseUrl, secretCipher: encryptJson(creds), enabled: true },
      create: { tenantId: tenant.id, type, name, baseUrl, secretCipher: encryptJson(creds), enabled: true },
    });
    console.log(`[seed] conector: ${type} · ${name}`);
  };

  let migrated = 0;
  if (connectorConfigured.wazuh()) {
    await upsertConnector('WAZUH', 'Wazuh principal', config.wazuh.indexerUrl || config.wazuh.apiUrl, {
      apiUrl: config.wazuh.apiUrl,
      apiUser: config.wazuh.apiUser,
      apiPassword: config.wazuh.apiPassword,
      indexerUrl: config.wazuh.indexerUrl,
      indexerUser: config.wazuh.indexerUser,
      indexerPassword: config.wazuh.indexerPassword,
      alertsIndex: config.wazuh.alertsIndex,
      insecureTLS: config.wazuh.insecureTLS,
    });
    migrated++;
  }
  if (connectorConfigured.misp()) {
    await upsertConnector('MISP', 'MISP principal', config.misp.url, {
      apiKey: config.misp.apiKey,
      insecureTLS: config.misp.insecureTLS,
    });
    migrated++;
  }
  if (connectorConfigured.thehive()) {
    await upsertConnector('THEHIVE', 'TheHive principal', config.thehive.url, {
      apiKey: config.thehive.apiKey,
      insecureTLS: config.thehive.insecureTLS,
    });
    migrated++;
  }
  console.log(`[seed] ${migrated} conector(es) migrado(s) do .env (cifrados).`);
  console.log('[seed] concluído.');
}

main()
  .catch((e) => {
    console.error('[seed] erro:', e?.message || e);
    process.exitCode = 1;
  })
  .finally(async () => {
    await disconnect();
  });
