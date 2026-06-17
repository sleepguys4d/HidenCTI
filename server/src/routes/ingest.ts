import crypto from 'node:crypto';
import { Router } from 'express';
import { config } from '../config.js';
import { isEnabled, effective } from '../services/connectors/runtime.js';
import { ingestWebhook, webhookStats } from '../ingest/webhook/index.js';

/**
 * Ingestão de máquina-para-máquina (push), autenticada por token — não por
 * sessão de utilizador. É montada fora da barreira de login para que soluções
 * externas possam enviar eventos diretamente.
 */
export const ingestRouter = Router();

function timingSafe(a: string, b: string): boolean {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  if (ab.length !== bb.length || ab.length === 0) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function webhookToken(): string {
  return String(effective('webhook').token || '') || config.webhook.token || '';
}

/** Webhook universal: qualquer solução externa envia eventos JSON aqui. */
ingestRouter.post('/webhook', (req, res) => {
  if (!isEnabled('webhook')) {
    res.status(503).json({ ok: false, error: 'Inbound webhook disabled. Enable it in Integrations.' });
    return;
  }
  const expected = webhookToken();
  if (!expected) {
    res.status(503).json({ ok: false, error: 'Ingestion token not configured.' });
    return;
  }
  const provided = String(req.get('x-socx-token') || req.query.token || '');
  if (!timingSafe(provided, expected)) {
    res.status(401).json({ ok: false, error: 'Invalid token.' });
    return;
  }
  const accepted = ingestWebhook(req.body, req.ip || '');
  res.json({ ok: true, accepted });
});

/** Estatísticas de ingestão por webhook (diagnóstico). */
ingestRouter.get('/webhook/stats', (_req, res) => {
  res.json(webhookStats());
});
