import { effective, isLive } from './runtime.js';
import type { ProviderFactory, SourceProvider, Capability } from './sdk.js';
import type { HealthState } from '../../types.js';

/**
 * Registo de provedores de dados. O agregador consome este registo de forma
 * genérica — não conhece Wazuh, MISP ou TheHive diretamente.
 */

const factories = new Map<string, ProviderFactory>();

export function registerProvider(key: string, factory: ProviderFactory): void {
  factories.set(key, factory);
}

export function hasProvider(key: string): boolean {
  return factories.has(key);
}

export function registeredKeys(): string[] {
  return [...factories.keys()];
}

/** Instancia um provedor com a configuração efetiva atual. */
export function buildProvider(key: string): SourceProvider | null {
  const factory = factories.get(key);
  if (!factory) return null;
  return factory({ key, config: effective(key) });
}

/**
 * Provedores "ao vivo" (ativados e configurados na GUI, fora do modo DEMO) que
 * oferecem uma dada capacidade. É a base da extensibilidade: assim que uma
 * integração nova é registada e ativada, passa a contribuir automaticamente.
 */
export function liveProviders(cap: Capability): SourceProvider[] {
  const out: SourceProvider[] = [];
  for (const key of factories.keys()) {
    if (!isLive(key)) continue;
    const p = buildProvider(key);
    if (p && p.capabilities.includes(cap) && typeof (p as unknown as Record<string, unknown>)[cap] === 'function') {
      out.push(p);
    }
  }
  return out;
}

/** Saúde de um conector via provedor (apenas quando ao vivo). */
export async function providerHealth(key: string): Promise<HealthState | null> {
  if (!isLive(key)) return null;
  const p = buildProvider(key);
  if (p?.health) {
    try { return await p.health(); } catch { return 'deg'; }
  }
  return null;
}
