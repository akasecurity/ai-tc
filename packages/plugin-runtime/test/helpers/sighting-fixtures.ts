import { createHmac } from 'node:crypto';

import type { SightingKey, SightingKeys } from '@akasecurity/persistence';

/** A value the bundled token rule detects, assembled at runtime from a seed. */
export function patShaped(seed: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let state = seed;
  let body = '';
  for (let i = 0; i < 36; i += 1) {
    state = (state * 1103515245 + 12345) % 2147483648;
    body += alphabet.charAt(state % alphabet.length);
  }
  return ['gh', 'p_', body].join('');
}

export const emailShaped = (): string => ['jane.doe', 'example.com'].join('@');

export function keyOf(keyVersion: number, seed: number): SightingKey {
  return {
    keyVersion,
    key: Uint8Array.from({ length: 32 }, (_, i) => (i * 29 + seed) % 256),
  };
}

export const keysOf = (current: SightingKey): SightingKeys => ({ current, previous: [] });

/** The expected token, computed here independently of the code under test. */
export function expectedToken(key: SightingKey, raw: string): string {
  const visible = raw.replace(/[\u200B\uFEFF]/g, '');
  const mac = createHmac('sha256', Buffer.from(key.key))
    .update(Buffer.concat([Buffer.from('aka:sighting:v1', 'utf8'), Buffer.from(visible, 'utf8')]))
    .digest('base64url');
  return `[[aka:fp:v${String(key.keyVersion)}.${mac}]]`;
}

/** The base64url material for a key, as the stored key map spells it. */
export const materialOf = (key: SightingKey): string => Buffer.from(key.key).toString('base64url');
