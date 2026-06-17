/**
 * Registo de conectores — o catálogo de integrações da plataforma.
 *
 * Cada tipo declara os seus metadados e o **esquema de campos**, que é o que a
 * interface gráfica usa para desenhar o formulário de configuração. Adicionar
 * uma integração nova passa a ser acrescentar uma entrada aqui (mais, quando
 * aplicável, o conector de dados) — sem alterar a interface.
 */

export type FieldType = 'text' | 'url' | 'password' | 'bool';

import type { Capability } from './sdk.js';

export interface ConnectorField {
  name: string;          // chave (igual à usada na config efetiva)
  label: string;
  type: FieldType;
  required?: boolean;
  secret?: boolean;      // guardado cifrado; nunca devolvido em texto simples
  placeholder?: string;
  help?: string;
  default?: string | boolean;
}

export interface ConnectorSpec {
  key: string;
  label: string;
  category: string;
  /** Conector de "push" (ex.: syslog) — recebe dados, não há teste de saída. */
  push?: boolean;
  /** Tem recolha de dados ativa (alimenta o stream/incidentes). */
  pull?: boolean;
  /** Suporta teste de ligação. */
  testable: boolean;
  /** Campo(s) que identificam o destino (guardados em claro: baseUrl/meta). */
  fields: ConnectorField[];
  /** Quais os campos obrigatórios para considerar "configurado". */
  requiredFor: string[];
}

const TLS_FIELD: ConnectorField = {
  name: 'insecureTLS', label: 'Accept self-signed TLS (lab)', type: 'bool', default: true,
  help: 'Turn off in production with a valid certificate.',
};

export const REGISTRY: ConnectorSpec[] = [
  {
    key: 'wazuh', label: 'Wazuh', category: 'SIEM / XDR', pull: true, testable: true,
    requiredFor: ['indexerUrl'],
    fields: [
      { name: 'indexerUrl', label: 'Indexer URL (OpenSearch)', type: 'url', required: true, placeholder: 'https://wazuh.local:9200' },
      { name: 'indexerUser', label: 'Indexer · user', type: 'text', placeholder: 'admin' },
      { name: 'indexerPassword', label: 'Indexer · password', type: 'password', secret: true },
      { name: 'alertsIndex', label: 'Índice de alertas', type: 'text', default: 'wazuh-alerts-*' },
      { name: 'apiUrl', label: 'Manager API URL', type: 'url', placeholder: 'https://wazuh.local:55000', help: 'Optional — health and agents.' },
      { name: 'apiUser', label: 'API · user', type: 'text' },
      { name: 'apiPassword', label: 'API · password', type: 'password', secret: true },
      TLS_FIELD,
    ],
  },
  {
    key: 'misp', label: 'MISP', category: 'Threat Intel', pull: true, testable: true,
    requiredFor: ['url', 'apiKey'],
    fields: [
      { name: 'url', label: 'URL', type: 'url', required: true, placeholder: 'https://misp.local' },
      { name: 'apiKey', label: 'AuthKey (API)', type: 'password', required: true, secret: true },
      TLS_FIELD,
    ],
  },
  {
    key: 'thehive', label: 'TheHive / Cortex', category: 'Case Mgmt / SOAR', pull: true, testable: true,
    requiredFor: ['url', 'apiKey'],
    fields: [
      { name: 'url', label: 'URL', type: 'url', required: true, placeholder: 'http://thehive.local:9000' },
      { name: 'apiKey', label: 'API Key', type: 'password', required: true, secret: true },
      TLS_FIELD,
    ],
  },
  {
    key: 'firewall-syslog', label: 'Firewall · Syslog', category: 'Ingestion (push)', push: true, testable: true,
    requiredFor: [],
    fields: [
      { name: 'udpPort', label: 'UDP port (container)', type: 'text', default: '5514', help: 'Mapped from 514 on the host.' },
      { name: 'tcpPort', label: 'TCP port (container)', type: 'text', default: '5514' },
      { name: 'tenantMap', label: 'IP→organization map', type: 'text', placeholder: '10.0.0.1=tenant-a,10.0.0.2=tenant-b', help: 'Optional — maps each firewall to a tenant (03.5).' },
    ],
  },
  {
    key: 'webhook', label: 'Inbound Webhook', category: 'Ingestion (push)', push: true, testable: true,
    requiredFor: ['token'],
    fields: [
      { name: 'token', label: 'Ingestion token', type: 'password', required: true, secret: true,
        help: 'Include in requests: X-SOCX-Token header, or ?token= in the URL.' },
      { name: 'note', label: 'Send URL', type: 'text', default: 'POST /api/ingest/webhook',
        help: 'Any external solution can send JSON events to this endpoint.' },
    ],
  },
  {
    key: 'opnsense', label: 'OPNsense', category: 'Firewall / NGFW', testable: true,
    requiredFor: ['url'],
    fields: [
      { name: 'url', label: 'URL', type: 'url', required: true, placeholder: 'https://opnsense.local' },
      { name: 'apiKey', label: 'API Key', type: 'password', secret: true },
      { name: 'apiSecret', label: 'API Secret', type: 'password', secret: true },
      TLS_FIELD,
    ],
  },
];

// Tipos genéricos (config + teste de alcançabilidade; recolha de dados em fase futura).
const GENERIC: { key: string; label: string; category: string }[] = [
  { key: 'malcolm', label: 'Malcolm / Zeek', category: 'NDR' },
  { key: 'velociraptor', label: 'Velociraptor', category: 'EDR' },
  { key: 'suricata', label: 'Suricata', category: 'IDS / IPS' },
  { key: 'graylog', label: 'Graylog', category: 'Log Pipeline' },
  { key: 'opencti', label: 'OpenCTI', category: 'Threat Intel' },
  { key: 'elastic', label: 'Elastic', category: 'SIEM / Search' },
];
for (const g of GENERIC) {
  REGISTRY.push({
    key: g.key, label: g.label, category: g.category, testable: true, requiredFor: ['url'],
    fields: [
      { name: 'url', label: 'URL', type: 'url', required: true, placeholder: `https://${g.key}.local` },
      { name: 'token', label: 'Token / API Key', type: 'password', secret: true },
      TLS_FIELD,
    ],
  });
}

const BY_KEY = new Map(REGISTRY.map((s) => [s.key, s]));
export const getSpec = (key: string): ConnectorSpec | undefined => BY_KEY.get(key);

/** Mapeia a chave do registo para o enum ConnectorType da base de dados. */
export function toConnectorType(key: string): string {
  if (key === 'firewall-syslog') return 'SYSLOG';
  return key.toUpperCase().replace(/-/g, '_');
}
