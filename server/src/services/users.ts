import { hash } from '@node-rs/argon2';
import { config } from '../config.js';
import { prisma, dbEnabled } from '../db/client.js';

/**
 * User management (sub-phase 03.3/03.4).
 *
 * Backed by the database. Users belong to the default tenant via a membership
 * that carries their role. Requires DB + an authenticated OWNER/ADMIN (enforced
 * by the route guards). Without a database, management is unavailable.
 */

export interface ManagedUser {
  id: string;
  email: string;
  name: string;
  role: string;
  status: string;
  createdAt: string;
}

const ROLES = ['OWNER', 'ADMIN', 'ANALYST', 'VIEWER', 'AUDITOR'];

export function usersAvailable(): boolean {
  return dbEnabled;
}

async function tenantId(): Promise<string | null> {
  const t = await prisma().tenant.findUnique({ where: { slug: config.defaultTenant.slug } });
  return t?.id || null;
}

export async function listUsers(): Promise<ManagedUser[]> {
  const tid = await tenantId();
  if (!tid) return [];
  const rows = await prisma().user.findMany({
    where: { memberships: { some: { tenantId: tid } } },
    include: { memberships: { where: { tenantId: tid } } },
    orderBy: { createdAt: 'asc' },
  });
  return rows.map((u: any) => ({
    id: u.id, email: u.email, name: u.name,
    role: u.memberships[0]?.role || 'ANALYST',
    status: u.status,
    createdAt: u.createdAt.toISOString(),
  }));
}

export async function createUser(input: { email: string; name: string; password: string; role: string }):
  Promise<{ ok: boolean; error?: string; user?: ManagedUser }> {
  const email = (input.email || '').trim().toLowerCase();
  const name = (input.name || '').trim();
  const role = ROLES.includes(input.role) ? input.role : 'ANALYST';
  if (!email || !name) return { ok: false, error: 'Email and name are required.' };
  if (!input.password || input.password.length < 8) return { ok: false, error: 'Password must be at least 8 characters.' };

  const tid = await tenantId();
  if (!tid) return { ok: false, error: 'Default tenant not found.' };

  const existing = await prisma().user.findUnique({ where: { email } });
  if (existing) return { ok: false, error: 'A user with this email already exists.' };

  const passwordHash = await hash(input.password);
  const user = await prisma().user.create({
    data: { email, name, passwordHash, status: 'ACTIVE' },
  });
  await prisma().membership.create({
    data: { userId: user.id, tenantId: tid, role: role as any, status: 'ACTIVE' },
  });
  await prisma().userPreference.create({ data: { userId: user.id, tenantId: tid } }).catch(() => {});

  return {
    ok: true,
    user: { id: user.id, email, name, role, status: 'ACTIVE', createdAt: user.createdAt.toISOString() },
  };
}

export async function updateUser(id: string, patch: { role?: string; status?: string }):
  Promise<{ ok: boolean; error?: string }> {
  const tid = await tenantId();
  if (!tid) return { ok: false, error: 'Default tenant not found.' };

  if (patch.role && ROLES.includes(patch.role)) {
    await prisma().membership.updateMany({ where: { userId: id, tenantId: tid }, data: { role: patch.role as any } });
  }
  if (patch.status && ['ACTIVE', 'DISABLED'].includes(patch.status)) {
    await prisma().user.update({ where: { id }, data: { status: patch.status as any } });
  }
  return { ok: true };
}

export async function deactivateUser(id: string): Promise<{ ok: boolean; error?: string }> {
  // Refuse to remove the last active OWNER.
  const tid = await tenantId();
  if (!tid) return { ok: false, error: 'Default tenant not found.' };
  const owners = await prisma().membership.count({
    where: { tenantId: tid, role: 'OWNER', user: { status: 'ACTIVE' } },
  });
  const target = await prisma().membership.findFirst({ where: { userId: id, tenantId: tid } });
  if (target?.role === 'OWNER' && owners <= 1) {
    return { ok: false, error: 'Cannot deactivate the last active owner.' };
  }
  await prisma().user.update({ where: { id }, data: { status: 'DISABLED' } });
  return { ok: true };
}

export { ROLES };
