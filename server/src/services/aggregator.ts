import { config } from '../config.js';
import * as mock from '../mock/data.js';
import { liveProviders, providerHealth } from './connectors/providers.js';
import { isEnabled } from './connectors/runtime.js';
import { syslogRecentEvents, syslogStats } from '../ingest/syslog/index.js';
import { webhookRecentEvents, webhookStats } from '../ingest/webhook/index.js';
import type { SecurityEvent, Incident, Integration } from '../types.js';

/**
 * O agregador é a fonte única de verdade para a interface. Descobre os
 * provedores de dados registados (genéricos — não conhece integrações
 * específicas), prefere dados ao vivo e recai no conjunto de demonstração para
 * a plataforma estar sempre populada.
 *
 * Qualquer integração nova que seja registada e ativada passa a contribuir
 * automaticamente para o stream, sem alterações aqui.
 */

const flat = <T>(batches: (T[] | null)[]): T[] => batches.flatMap((b) => b || []);

export async function getEvents(): Promise<{ data: SecurityEvent[]; live: boolean }> {
  // Eventos push (mais recentes) — firewalls por syslog + webhook de entrada.
  const push = [...syslogRecentEvents(undefined, 40), ...webhookRecentEvents(40)];
  const pushLive = !config.demoMode && push.length > 0;

  const providers = liveProviders('events');
  if (providers.length) {
    const live = flat(await Promise.all(providers.map((p) => p.events!(60).catch(() => null))));
    if (live.length || push.length) {
      return { data: [...push, ...live].slice(0, 100), live: live.length > 0 || pushLive };
    }
  }
  return { data: [...push, ...mock.events].slice(0, 100), live: pushLive };
}

export async function getIncidents(): Promise<{ data: Incident[]; live: boolean }> {
  const providers = liveProviders('incidents');
  if (providers.length) {
    const live = flat(await Promise.all(providers.map((p) => p.incidents!(40).catch(() => null))));
    if (live.length) return { data: live.slice(0, 80), live: true };
  }
  return { data: mock.incidents, live: false };
}

export async function enrichIoc(ioc: string) {
  const providers = liveProviders('enrich');
  if (providers.length) {
    const matches = flat(await Promise.all(providers.map((p) => p.enrich!(ioc).catch(() => null))));
    if (matches.length) return { ioc, matches, live: true };
  }
  return { ioc, matches: [], live: false };
}

export async function getIntegrations(): Promise<Integration[]> {
  const list = mock.integrations.map((i) => ({ ...i }));

  // Saúde real via provedores (qualquer integração registada e ao vivo).
  if (!config.demoMode) {
    await Promise.all(list.map(async (i) => {
      const h = await providerHealth(i.key);
      if (h) i.state = h;
    }));
  }

  // Recetor de syslog (push) — estatísticas reais de ingestão.
  const fw = list.find((i) => i.key === 'firewall-syslog');
  if (fw) {
    const s = syslogStats();
    if (s.enabled) {
      fw.state = 'on';
      fw.eps = s.eps >= 1 ? `${s.eps.toFixed(1)}/s` : `${s.epsLastMinute}/min`;
      fw.events = String(s.total);
      fw.rules = `${s.blocked} blocks`;
    } else if (!config.demoMode) {
      fw.state = 'off';
    }
  }

  // Webhook de entrada (push) — estatísticas reais.
  const wh = list.find((i) => i.key === 'webhook');
  if (wh) {
    const s = webhookStats();
    const on = isEnabled('webhook');
    wh.state = on ? 'on' : (config.demoMode ? wh.state : 'off');
    wh.eps = s.eps >= 1 ? `${s.eps.toFixed(1)}/s` : `${s.epsLastMinute}/min`;
    wh.events = String(s.total);
  }
  return list;
}

export async function getDashboard() {
  const integrations = await getIntegrations();
  const online = integrations.filter((i) => i.state === 'on').length;
  const summary = structuredClone(mock.dashboard);
  summary.kpis = summary.kpis.map((k) =>
    k.label.startsWith('Sensores') ? { ...k, value: `${online}/${integrations.length}` } : k,
  );
  return { ...summary, integrations, mode: config.demoMode ? 'demo' : 'live' };
}
