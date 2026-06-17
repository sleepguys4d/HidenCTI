import crypto from 'node:crypto';
import { verify } from '@node-rs/argon2';
import { config } from '../config.js';
import { prisma, dbEnabled } from '../db/client.js';

/**
 * Serviço de autenticação.
 *
 * Modo de produção (login obrigatório) ativa-se automaticamente quando existe
 * um administrador — seja na base de dados (criado pelo seed) ou via
 * ADMIN_PASSWORD no ambiente. Sem administrador configurado, a consola corre
 * em modo aberto (demonstração), como antes. AUTH_REQUIRED=true força o login.
 */

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: string;
}

let _required: boolean | null = null;

/** Determina (e memoiza) se o login é obrigatório. */
export async function initAuth(): Promise<void> {
  if (config.auth.force || config.admin.password) { _required = true; return; }
  if (dbEnabled) {
    try {
      const count = await prisma().user.count();
      _required = count > 0;
      return;
    } catch {
      /* sem BD acessível */
    }
  }
  _required = false;
}

export function authRequired(): boolean {
  return _required ?? Boolean(config.admin.password || config.auth.force);
}

function timingSafeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    // Comparação de comprimento diferente — ainda assim em tempo constante simbólico.
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

async function roleFor(userId: string): Promise<string> {
  try {
    const m = await prisma().membership.findFirst({
      where: { userId, tenant: { slug: config.defaultTenant.slug } },
    });
    return m?.role || 'ANALYST';
  } catch {
    return 'ANALYST';
  }
}

/** Verifica credenciais. Devolve o utilizador ou null. */
export async function verifyLogin(email: string, password: string): Promise<AuthUser | null> {
  const e = (email || '').trim().toLowerCase();
  if (!e || !password) return null;

  if (dbEnabled) {
    try {
      const user = await prisma().user.findUnique({ where: { email: e } });
      if (user && user.status === 'ACTIVE' && user.passwordHash) {
        const ok = await verify(user.passwordHash, password);
        if (ok) return { id: user.id, email: user.email, name: user.name, role: await roleFor(user.id) };
        return null;
      }
    } catch {
      /* cai para o fallback de ambiente */
    }
  }

  // Fallback de ambiente (sem BD): admin único definido por ADMIN_PASSWORD.
  if (config.admin.password && e === config.admin.email.toLowerCase() && timingSafeEqual(password, config.admin.password)) {
    return { id: 'env:admin', email: config.admin.email, name: config.admin.name, role: 'OWNER' };
  }
  return null;
}

/** Resolve o utilizador a partir do id guardado na sessão. */
export async function getUser(userId: string): Promise<AuthUser | null> {
  if (userId === 'env:admin') {
    return { id: 'env:admin', email: config.admin.email, name: config.admin.name, role: 'OWNER' };
  }
  if (dbEnabled) {
    try {
      const user = await prisma().user.findUnique({ where: { id: userId } });
      if (user && user.status === 'ACTIVE') {
        return { id: user.id, email: user.email, name: user.name, role: await roleFor(user.id) };
      }
    } catch {
      /* ignora */
    }
  }
  return null;
}
