import { registerProvider } from './providers.js';
import { wazuhProvider } from '../../connectors/wazuh.js';
import { mispProvider } from '../../connectors/misp.js';
import { thehiveProvider } from '../../connectors/thehive.js';

/**
 * Regista os provedores nativos. Para adicionar uma integração nova, registe
 * aqui o seu ProviderFactory (ver providers/_example.ts).
 */
export function registerBuiltinProviders(): void {
  registerProvider('wazuh', wazuhProvider);
  registerProvider('misp', mispProvider);
  registerProvider('thehive', thehiveProvider);
}
