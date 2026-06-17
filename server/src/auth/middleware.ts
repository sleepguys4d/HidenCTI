import type { Request, Response, NextFunction } from 'express';
import { authRequired, getUser, type AuthUser } from './service.js';
import { validateSession } from './sessions.js';

/** Nome do cookie de sessão. */
export const COOKIE = 'socx_sess';

export interface AuthedRequest extends Request {
  user?: AuthUser;
}

/**
 * Protege a API. Em modo aberto (sem administrador configurado) deixa passar;
 * caso contrário exige uma sessão válida.
 */
export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (!authRequired()) { next(); return; }
  const token = (req as Request & { cookies?: Record<string, string> }).cookies?.[COOKIE];
  const userId = await validateSession(token);
  if (!userId) { res.status(401).json({ error: 'unauthorized', message: 'Invalid or expired session.' }); return; }
  const user = await getUser(userId);
  if (!user) { res.status(401).json({ error: 'unauthorized' }); return; }
  (req as AuthedRequest).user = user;
  next();
}

/** Exige que o utilizador tenha um dos papéis indicados (defesa em profundidade). */
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!authRequired()) { next(); return; }
    const user = (req as AuthedRequest).user;
    if (!user || !roles.includes(user.role)) {
      res.status(403).json({ error: 'forbidden', message: 'You do not have permission for this action.' });
      return;
    }
    next();
  };
}
