import crypto from 'node:crypto';
import { config } from '../config.js';
import { prisma, dbEnabled } from '../db/client.js';

/**
 * Sessões de utilizador. Persistem na base de dados (modelo `Session`) quando
 * disponível; caso contrário ficam em memória (instância única). O cookie do
 * cliente guarda o token; o servidor guarda apenas o seu hash (sha256).
 */

interface MemSession { userId: string; expiresAt: number }
const memSessions = new Map<string, MemSession>();

const sha256 = (s: string): string => crypto.createHash('sha256').update(s).digest('hex');
const ttlMs = () => config.auth.sessionTtlHours * 3600 * 1000;

export interface SessionInfo { token: string; expiresAt: Date }

export async function createSession(userId: string, ip?: string, ua?: string): Promise<SessionInfo> {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = sha256(token);
  const expiresAt = new Date(Date.now() + ttlMs());

  if (dbEnabled && !userId.startsWith('env:')) {
    try {
      await prisma().session.create({ data: { userId, tokenHash, ip, userAgent: ua?.slice(0, 250), expiresAt } });
      return { token, expiresAt };
    } catch {
      /* cai para memória */
    }
  }
  memSessions.set(tokenHash, { userId, expiresAt: expiresAt.getTime() });
  return { token, expiresAt };
}

export async function validateSession(token: string | undefined): Promise<string | null> {
  if (!token) return null;
  const tokenHash = sha256(token);

  const mem = memSessions.get(tokenHash);
  if (mem) {
    if (mem.expiresAt < Date.now()) { memSessions.delete(tokenHash); return null; }
    return mem.userId;
  }
  if (dbEnabled) {
    try {
      const s = await prisma().session.findUnique({ where: { tokenHash } });
      if (!s) return null;
      if (s.expiresAt.getTime() < Date.now()) {
        await prisma().session.delete({ where: { tokenHash } }).catch(() => {});
        return null;
      }
      return s.userId;
    } catch {
      return null;
    }
  }
  return null;
}

export async function revokeSession(token: string | undefined): Promise<void> {
  if (!token) return;
  const tokenHash = sha256(token);
  memSessions.delete(tokenHash);
  if (dbEnabled) {
    try { await prisma().session.delete({ where: { tokenHash } }); } catch { /* já removida */ }
  }
}
