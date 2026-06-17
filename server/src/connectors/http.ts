import axios, { type AxiosInstance, type AxiosRequestConfig } from 'axios';
import https from 'node:https';

/**
 * Build an axios client. Self-hosted SOC tooling (Wazuh, MISP, TheHive) is
 * routinely deployed with self-signed certificates, so insecureTLS is allowed
 * but defaults to off for anything reachable over the public internet.
 */
export function httpClient(baseURL: string, insecureTLS = false, extra: AxiosRequestConfig = {}): AxiosInstance {
  return axios.create({
    baseURL,
    timeout: 12000,
    httpsAgent: insecureTLS ? new https.Agent({ rejectUnauthorized: false }) : undefined,
    ...extra,
  });
}

export function logConnectorError(name: string, err: unknown): void {
  const msg = axios.isAxiosError(err)
    ? `${err.code || ''} ${err.response?.status || ''} ${err.message}`
    : (err as Error)?.message || String(err);
  console.warn(`[connector:${name}] indisponível, a usar fallback — ${msg}`);
}
