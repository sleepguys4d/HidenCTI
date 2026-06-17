import crypto from 'node:crypto';

/**
 * Envelope encryption for connector credentials (and any secret at rest).
 * AES-256-GCM with a per-secret random IV. Format: v1.<iv>.<tag>.<ciphertext>
 * (all base64). The master key comes from APP_ENCRYPTION_KEY.
 *
 * For 03.1 the key may be supplied as 32-byte base64/hex, or any passphrase
 * (derived to 32 bytes via SHA-256). Production note: use a real 32-byte random
 * key (`openssl rand -base64 32`) and rotate via KMS.
 */

const ALG = 'aes-256-gcm';

function masterKey(): Buffer {
  const raw = process.env.APP_ENCRYPTION_KEY || '';
  if (!raw) throw new Error('APP_ENCRYPTION_KEY em falta — não é possível cifrar/decifrar segredos.');
  if (/^[A-Fa-f0-9]{64}$/.test(raw)) return Buffer.from(raw, 'hex');
  const b64 = Buffer.from(raw, 'base64');
  if (b64.length === 32) return b64;
  // Deterministic fallback so any passphrase works; logged as non-ideal.
  return crypto.createHash('sha256').update(raw, 'utf8').digest();
}

export function encryptSecret(plain: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALG, masterKey(), iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${iv.toString('base64')}.${tag.toString('base64')}.${enc.toString('base64')}`;
}

export function decryptSecret(payload: string): string {
  const parts = payload.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') throw new Error('Formato de segredo inválido.');
  const [, ivb, tagb, datab] = parts;
  const decipher = crypto.createDecipheriv(ALG, masterKey(), Buffer.from(ivb, 'base64'));
  decipher.setAuthTag(Buffer.from(tagb, 'base64'));
  const dec = Buffer.concat([decipher.update(Buffer.from(datab, 'base64')), decipher.final()]);
  return dec.toString('utf8');
}

export function encryptJson(obj: unknown): string {
  return encryptSecret(JSON.stringify(obj));
}

export function decryptJson<T = unknown>(payload: string): T {
  return JSON.parse(decryptSecret(payload)) as T;
}

/** True when an encryption key is configured (so callers can degrade gracefully). */
export const encryptionAvailable = (): boolean => Boolean(process.env.APP_ENCRYPTION_KEY);
