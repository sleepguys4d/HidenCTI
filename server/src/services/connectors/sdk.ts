import type { SecurityEvent, Incident, HealthState } from '../../types.js';

/**
 * SDK de conectores — o contrato que qualquer integração de dados implementa.
 *
 * O agregador não conhece integrações específicas: descobre os provedores
 * registados e pede-lhes dados conforme as capacidades que declaram. Adicionar
 * uma solução nova (Elastic, Graylog, OpenCTI, um SIEM próprio, uma API de um
 * parceiro…) passa a ser:
 *   1. declarar a integração no registo (`registry.ts`) — desenha o formulário;
 *   2. implementar um `ProviderFactory` com as capacidades que fizerem sentido;
 *   3. registá-lo em `register.ts`.
 * Nada no núcleo precisa de mudar.
 */

/** Capacidades possíveis. O nome da capacidade é também o nome do método. */
export type Capability = 'health' | 'events' | 'incidents' | 'enrich';

/** Resultado de enriquecimento de um indicador (IOC). */
export interface IntelMatch {
  value: string;
  type: string;
  category: string;
  event: string;
  threatLevel: string;
  tags: string[];
}

/** Contexto entregue à fábrica: a configuração efetiva já resolvida (GUI/.env). */
export interface ConnectorContext {
  key: string;
  config: Record<string, unknown>;
}

/**
 * Um provedor de dados. Implementa apenas os métodos correspondentes às
 * capacidades que declara em `capabilities` (o resto fica por definir).
 */
export interface SourceProvider {
  key: string;
  label: string;
  capabilities: Capability[];
  /** Estado de saúde do alvo. */
  health?(): Promise<HealthState>;
  /** Eventos/alertas recentes para o stream unificado. */
  events?(limit: number): Promise<SecurityEvent[] | null>;
  /** Incidentes/casos para o quadro de incidentes. */
  incidents?(limit: number): Promise<Incident[] | null>;
  /** Enriquecimento de um IOC (IP, hash, domínio…). */
  enrich?(ioc: string): Promise<IntelMatch[] | null>;
}

/** Constrói um provedor a partir da configuração efetiva do conector. */
export type ProviderFactory = (ctx: ConnectorContext) => SourceProvider;
