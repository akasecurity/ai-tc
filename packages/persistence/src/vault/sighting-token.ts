import { createHmac } from 'node:crypto';

import { SIGHTING_ALIASES_MAX, stripInvisiblePadding } from '@akasecurity/schema';

import type { SightingKey, SightingKeys } from './sighting-keys.ts';

/** The domain string prefixed to every value before it is hashed. */
export const SIGHTING_DOMAIN = 'aka:sighting:v1';

/**
 * The sighting token for a secret value:
 * `[[aka:fp:v<keyVersion>.<base64url(HMAC-SHA256(key, domain ‖ value))>]]`,
 * with invisible padding removed from the value first.
 */
export function sightingToken(key: SightingKey, raw: string): string {
  const mac = createHmac('sha256', key.key)
    .update(SIGHTING_DOMAIN, 'utf8')
    .update(stripInvisiblePadding(raw), 'utf8')
    .digest('base64url');
  return `[[aka:fp:v${String(key.keyVersion)}.${mac}]]`;
}

/** A value's sighting token, and its tokens under each previous version held. */
export interface SightingTokens {
  token: string;
  aliases?: string[];
}

/**
 * The value's token under the current version and, as `aliases`, under each
 * previous version `keys` holds, in the order it holds them and at most
 * {@link SIGHTING_ALIASES_MAX}. No `aliases` member when there are none.
 */
export function sightingTokens(keys: SightingKeys, raw: string): SightingTokens {
  const token = sightingToken(keys.current, raw);
  const previous = keys.previous.slice(0, SIGHTING_ALIASES_MAX);
  if (previous.length === 0) return { token };
  return { token, aliases: previous.map((key) => sightingToken(key, raw)) };
}
