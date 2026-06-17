import { Router, type Request } from 'express';
import { config } from '../config.js';
import { authRequired, verifyLogin, getUser } from '../auth/service.js';
import { createSession, validateSession, revokeSession } from '../auth/sessions.js';
import { COOKIE } from '../auth/middleware.js';

export const authRouter = Router();

const cookies = (req: Request): Record<string, string> =>
  (req as Request & { cookies?: Record<string, string> }).cookies || {};

function cookieOpts(expires: Date) {
  return {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: config.auth.secureCookies,
    path: '/',
    expires,
  };
}

/** Estado de autenticação + utilizador atual (público — usado pela interface). */
authRouter.get('/me', async (req, res, next) => {
  try {
    const userId = await validateSession(cookies(req)[COOKIE]);
    const user = userId ? await getUser(userId) : null;
    res.json({ authRequired: authRequired(), user });
  } catch (e) { next(e); }
});

/** Início de sessão. */
authRouter.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    const user = await verifyLogin(String(email || ''), String(password || ''));
    if (!user) { res.status(401).json({ ok: false, error: 'Invalid credentials.' }); return; }
    const { token, expiresAt } = await createSession(user.id, req.ip, req.get('user-agent') || undefined);
    res.cookie(COOKIE, token, cookieOpts(expiresAt));
    res.json({ ok: true, user });
  } catch (e) { next(e); }
});

/** Fim de sessão. */
authRouter.post('/logout', async (req, res, next) => {
  try {
    await revokeSession(cookies(req)[COOKIE]);
    res.clearCookie(COOKIE, { path: '/' });
    res.json({ ok: true });
  } catch (e) { next(e); }
});
