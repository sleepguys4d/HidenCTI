import { httpClient, logConnectorError } from '../../../connectors/http.js';
import type { ProviderFactory } from '../sdk.js';
import type { SecurityEvent, Severity } from '../../../types.js';

/**
 * ╔══════════════════════════════════════════════════════════════════════╗
 * ║  MODELO DE CONECTOR — copie este ficheiro para criar uma integração   ║
 * ╚══════════════════════════════════════════════════════════════════════╝
 *
 * Este é um exemplo completo e comentado de como ligar uma solução nova
 * (aqui, um SIEM fictício "Acme") à plataforma. NÃO está registado — serve de
 * ponto de partida. Para criar uma integração real:
 *
 *   1) REGISTO (services/connectors/registry.ts)
 *      Acrescente uma entrada com a chave, rótulo, categoria e o esquema de
 *      campos. O esquema desenha automaticamente o formulário na GUI:
 *
 *        {
 *          key: 'acme', label: 'Acme SIEM', category: 'SIEM', pull: true, testable: true,
 *          requiredFor: ['url', 'apiKey'],
 *          fields: [
 *            { name: 'url',    label: 'URL',     type: 'url',      required: true },
 *            { name: 'apiKey', label: 'API Key', type: 'password', required: true, secret: true },
 *            { name: 'insecureTLS', label: 'Aceitar TLS self-signed', type: 'bool', default: true },
 *          ],
 *        }
 *
 *   2) IMPLEMENTAÇÃO (este ficheiro)
 *      Escreva um ProviderFactory que devolve as capacidades que fizerem
 *      sentido: 'health', 'events', 'incidents', 'enrich'. Implemente só os
 *      métodos correspondentes.
 *
 *   3) REGISTO DO PROVEDOR (services/connectors/register.ts)
 *        import { acmeProvider } from './providers/_example.js';
 *        registerProvider('acme', acmeProvider);
 *
 * Nada no núcleo precisa de mudar: o agregador descobre o provedor, e a GUI
 * passa a permitir configurá-lo, testá-lo e ativá-lo. Credenciais cifradas,
 * saúde e teste de ligação ficam automáticos.
 */

function mapSeverity(n: number): Severity {
  if (n >= 9) return 'crit';
  if (n >= 7) return 'high';
  if (n >= 4) return 'med';
  if (n >= 2) return 'low';
  return 'info';
}

export const acmeProvider: ProviderFactory = (ctx) => {
  // A configuração efetiva chega já resolvida (valores da GUI ou do .env).
  const url = String(ctx.config.url || '');
  const apiKey = String(ctx.config.apiKey || '');
  const insecure = Boolean(ctx.config.insecureTLS);

  const client = () =>
    httpClient(url, insecure, { headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' } });

  return {
    key: ctx.key,
    label: 'Acme SIEM',
    capabilities: ['health', 'events'],

    async health() {
      try {
        const { status } = await client().get('/api/status');
        return status === 200 ? 'on' : 'deg';
      } catch (err) {
        logConnectorError('acme-health', err);
        return 'deg';
      }
    },

    async events(limit: number): Promise<SecurityEvent[] | null> {
      try {
        const { data } = await client().get(`/api/alerts?limit=${limit}`);
        const rows: any[] = data?.results || [];
        return rows.map((r, i): SecurityEvent => ({
          id: r.id || `ACME-${i}`,
          time: String(r.timestamp || '').slice(11, 19) || '—',
          severity: mapSeverity(Number(r.severity || 0)),
          source: 'Acme SIEM',
          rule: r.rule_name || 'Alerta Acme',
          technique: r.mitre || '—',
          host: r.host || '—',
          srcIp: r.src_ip || '—',
          dstIp: r.dst_ip || '—',
          user: r.user || '—',
        }));
      } catch (err) {
        logConnectorError('acme-events', err);
        return null;
      }
    },
  };
};
