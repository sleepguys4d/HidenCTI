import { PrismaClient } from '@prisma/client';

/**
 * Database access with graceful degradation. When DATABASE_URL is absent the
 * platform keeps running in "legacy" mode (config from .env, demo data), so the
 * single-container demo continues to work exactly as before Phase 03.
 */

export const dbEnabled = Boolean(process.env.DATABASE_URL);

let _prisma: PrismaClient | null = null;

export function prisma(): PrismaClient {
  if (!_prisma) {
    _prisma = new PrismaClient({ log: ['warn', 'error'] });
  }
  return _prisma;
}

/** Returns true only if a DB is configured AND reachable. Never throws. */
export async function dbHealthy(): Promise<boolean> {
  if (!dbEnabled) return false;
  try {
    await prisma().$queryRaw`SELECT 1`;
    return true;
  } catch {
    return false;
  }
}

export async function disconnect(): Promise<void> {
  if (_prisma) await _prisma.$disconnect();
}
