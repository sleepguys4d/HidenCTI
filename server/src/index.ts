import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { config, dbEnabled } from './config.js';
import { api } from './routes/api.js';
import { authRouter } from './routes/auth.js';
import { ingestRouter } from './routes/ingest.js';
import { requireAuth } from './auth/middleware.js';
import { initAuth, authRequired } from './auth/service.js';
import { dbHealthy } from './db/client.js';
import { resolveConnectors } from './services/tenantConfig.js';
import { seedSyslogDemo, enableSyslog, stopSyslog, setTenantMap } from './ingest/syslog/index.js';
import { seedWebhookDemo } from './ingest/webhook/index.js';
import { initRuntime, registerSideEffect, isEnabled, effective } from './services/connectors/runtime.js';
import { registerBuiltinProviders } from './services/connectors/register.js';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Atrás de um reverse proxy (TLS): IP real + cookies Secure corretos.
app.set('trust proxy', config.trustProxy);

app.use(helmet({
  contentSecurityPolicy: config.cspEnabled ? {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'self'"],
      upgradeInsecureRequests: null,
    },
  } : false,
  crossOriginEmbedderPolicy: false,
}));
app.use(compression());
app.use(cors({ origin: config.corsOrigin, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(morgan('tiny'));

app.use('/api', rateLimit({ windowMs: 60_000, max: 240, standardHeaders: true, legacyHeaders: false }));

// Saúde — público (usado pelo healthcheck do contentor).
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'soc-xpert', mode: config.demoMode ? 'demo' : 'live', ts: new Date().toISOString() });
});

// Autenticação — público, com limite específico no login.
const loginLimiter = rateLimit({ windowMs: 60_000, max: 10, standardHeaders: true, legacyHeaders: false });
app.use('/api/auth/login', loginLimiter);
app.use('/api/auth', authRouter);

// Ingestão máquina-a-máquina (push) — autenticada por token, fora do login.
const ingestLimiter = rateLimit({ windowMs: 60_000, max: 600, standardHeaders: true, legacyHeaders: false });
app.use('/api/ingest', ingestLimiter, ingestRouter);

// Restante API — protegida quando o login é obrigatório.
app.use('/api', requireAuth, api);

// Serve the built frontend (single-container production deployment).
const webDist = path.resolve(__dirname, '../../web/dist');
app.use(express.static(webDist));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  res.sendFile(path.join(webDist, 'index.html'), (err) => err && next());
});

// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('[error]', err?.message || err);
  res.status(500).json({ error: 'internal_error', message: err?.message || 'erro interno' });
});

/** Em produção, recusa arrancar com configuração insegura óbvia. */
function assertProductionSafety(): void {
  if (config.nodeEnv !== 'production') return;
  const placeholder = 'troca-esta-chave-por-uma-de-32-bytes';
  const key = config.security.encryptionKey;
  if (dbEnabled && (!key || key === placeholder || key.length < 16)) {
    console.error('\n  ✗ [FATAL] APP_ENCRYPTION_KEY em falta, por defeito ou demasiado curta em produção.');
    console.error('    As credenciais dos conectores não podem ser cifradas em segurança.');
    console.error('    Gere uma chave forte e defina-a antes de arrancar:');
    console.error('        openssl rand -base64 32\n');
    process.exit(1);
  }
}

assertProductionSafety();
registerBuiltinProviders();

app.listen(config.port, () => {
  console.log(`\n  ╔══════════════════════════════════════════════╗`);
  console.log(`  ║   SOC Xpert · Sec4data Cyber Defense          ║`);
  console.log(`  ║   API em http://0.0.0.0:${config.port}                  ║`);
  console.log(`  ║   Modo: ${config.demoMode ? 'DEMO (dados simulados)   ' : 'LIVE (conectores reais)  '}             ║`);
  console.log(`  ╚══════════════════════════════════════════════╝\n`);
  seedSyslogDemo();
  seedWebhookDemo();
  // O toggle de syslog na GUI liga/desliga o recetor em tempo real.
  registerSideEffect('firewall-syslog', (enabled, fields) => {
    setTenantMap(String(fields.tenantMap || ''));
    if (enabled) enableSyslog(); else stopSyslog();
  });
  void bootRuntime();
});

/** Carrega a configuração de conectores e arranca o syslog conforme o estado efetivo. */
async function bootRuntime(): Promise<void> {
  await initRuntime();
  await initAuth();
  if (isEnabled('firewall-syslog')) {
    setTenantMap(String(effective('firewall-syslog').tenantMap || ''));
    enableSyslog();
  } else {
    console.log('  · Ingestão de syslog: desativada (ative na GUI ou no .env)');
  }
  console.log(`  · Autenticação: ${authRequired() ? 'OBRIGATÓRIA (login)' : 'aberta (modo demonstração)'}`);
  if (config.nodeEnv === 'production') {
    if (!authRequired()) console.warn('  ! AVISO: produção sem login obrigatório. Defina ADMIN_PASSWORD ou AUTH_REQUIRED=true.');
    if (config.demoMode) console.warn('  ! AVISO: produção em modo DEMO. Defina DEMO_MODE=false para usar conectores reais.');
    if (!config.auth.secureCookies) console.warn('  ! AVISO: cookies sem Secure. Atrás de TLS, defina COOKIE_SECURE=true.');
  }
  await reportFoundationStatus();
}

/** Logs Phase-03 foundation status without ever blocking or crashing boot. */
async function reportFoundationStatus(): Promise<void> {
  try {
    if (dbEnabled) {
      const ok = await dbHealthy();
      console.log(`  · Base de dados: ${ok ? 'ligada' : 'configurada mas inacessível (modo legado)'}`);
    } else {
      console.log('  · Base de dados: não configurada (modo legado · .env)');
    }
    const conn = await resolveConnectors();
    console.log(`  · Origem dos conectores: ${conn.source === 'db' ? 'base de dados (por tenant)' : '.env (global)'}\n`);
  } catch {
    /* status is best-effort only */
  }
}
