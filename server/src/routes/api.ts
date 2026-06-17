import { Router } from 'express';
import { config } from '../config.js';
import {
  getEvents, getIncidents, getIntegrations, getDashboard, enrichIoc,
} from '../services/aggregator.js';
import { copilotChat } from '../services/copilot.js';
import { thehiveCreateCase } from '../connectors/thehive.js';
import { syslogStats } from '../ingest/syslog/index.js';
import { listForUi, upsert, setEnabled, remove } from '../services/connectors/runtime.js';
import { testConnector } from '../services/connectors/test.js';
import { requireRole } from '../auth/middleware.js';
import { usersAvailable, listUsers, createUser, updateUser, deactivateUser } from '../services/users.js';
import * as mock from '../mock/data.js';

export const api = Router();

api.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'soc-xpert', mode: config.demoMode ? 'demo' : 'live', ts: new Date().toISOString() });
});

api.get('/dashboard', async (_req, res, next) => {
  try { res.json(await getDashboard()); } catch (e) { next(e); }
});

api.get('/events', async (req, res, next) => {
  try {
    const { data, live } = await getEvents();
    const sev = String(req.query.severity || 'all');
    const filtered = sev === 'all' ? data : data.filter((e) => e.severity === sev);
    res.json({ data: filtered, live });
  } catch (e) { next(e); }
});

api.get('/incidents', async (_req, res, next) => {
  try { res.json(await getIncidents()); } catch (e) { next(e); }
});

api.post('/incidents', async (req, res, next) => {
  try {
    const { title, description, severity } = req.body || {};
    const id = await thehiveCreateCase(title || 'Novo incidente', description || '', severity || 2);
    res.json({ created: true, id: id || `INC-2026-${Math.floor(Math.random() * 9000 + 1000)}`, live: Boolean(id) });
  } catch (e) { next(e); }
});

api.get('/integrations', async (_req, res, next) => {
  try { res.json({ data: await getIntegrations(), mode: config.demoMode ? 'demo' : 'live' }); } catch (e) { next(e); }
});

api.get('/syslog/stats', (_req, res) => {
  res.json(syslogStats());
});

// ── User management (sub-phase 03.3/03.4) ──
api.get('/users', requireRole('OWNER', 'ADMIN'), async (_req, res, next) => {
  try {
    if (!usersAvailable()) { res.json({ data: [], available: false }); return; }
    res.json({ data: await listUsers(), available: true });
  } catch (e) { next(e); }
});

api.post('/users', requireRole('OWNER', 'ADMIN'), async (req, res, next) => {
  try {
    if (!usersAvailable()) { res.status(503).json({ ok: false, error: 'User management requires a database.' }); return; }
    const { email, name, password, role } = req.body || {};
    const r = await createUser({ email, name, password, role });
    res.status(r.ok ? 200 : 400).json(r);
  } catch (e) { next(e); }
});

api.patch('/users/:id', requireRole('OWNER', 'ADMIN'), async (req, res, next) => {
  try {
    const { role, status } = req.body || {};
    res.json(await updateUser(req.params.id, { role, status }));
  } catch (e) { next(e); }
});

api.delete('/users/:id', requireRole('OWNER'), async (req, res, next) => {
  try { res.json(await deactivateUser(req.params.id)); } catch (e) { next(e); }
});

// ── Gestão de integrações por GUI ──
api.get('/connectors', (_req, res) => {
  res.json({ data: listForUi(), mode: config.demoMode ? 'demo' : 'live' });
});

api.post('/connectors/:key', requireRole('OWNER','ADMIN'), async (req, res, next) => {
  try {
    const { enabled, fields } = req.body || {};
    const r = await upsert(req.params.key, { enabled, fields });
    res.status(r.ok ? 200 : 400).json(r);
  } catch (e) { next(e); }
});

api.post('/connectors/:key/enable', requireRole('OWNER','ADMIN'), async (req, res, next) => {
  try {
    const r = await setEnabled(req.params.key, Boolean(req.body?.enabled));
    res.json(r);
  } catch (e) { next(e); }
});

api.post('/connectors/:key/test', async (req, res, next) => {
  try { res.json(await testConnector(req.params.key)); } catch (e) { next(e); }
});

api.delete('/connectors/:key', requireRole('OWNER','ADMIN'), async (req, res, next) => {
  try { await remove(req.params.key); res.json({ ok: true }); } catch (e) { next(e); }
});

api.get('/hunting/saved', (_req, res) => res.json({ data: mock.savedHunts }));

api.post('/hunting/run', async (_req, res) => {
  // Simulated hunt execution against the unified data lake.
  await new Promise((r) => setTimeout(r, 600));
  res.json({
    elapsed: '2.4s',
    scanned: 1_180_000,
    hits: [
      { host: 'FIN-WS-014', rdp: '14:33:10', lsass: '14:28:47', delta: '4m 23s', severity: 'crit' },
      { host: 'IT-WS-002', rdp: '14:31:02', lsass: '14:34:50', delta: '3m 48s', severity: 'high' },
      { host: 'HR-WS-009', rdp: '13:58:14', lsass: '14:01:33', delta: '3m 19s', severity: 'high' },
    ],
  });
});

api.get('/response/actions', (_req, res) => res.json({ data: mock.responseActions }));

api.post('/response/run', requireRole('OWNER','ADMIN','ANALYST'), (req, res) => {
  const { playbook, target } = req.body || {};
  res.json({ started: true, playbook, target, ticket: `RSP-${Date.now().toString().slice(-6)}` });
});

api.get('/intel/:ioc', async (req, res, next) => {
  try { res.json(await enrichIoc(req.params.ioc)); } catch (e) { next(e); }
});

api.post('/copilot', async (req, res, next) => {
  try {
    const messages = Array.isArray(req.body?.messages) ? req.body.messages : [];
    res.json(await copilotChat(messages));
  } catch (e) { next(e); }
});
