import { createHmac } from 'node:crypto';

import type { SightingKey, SightingKeys } from '@akasecurity/persistence';
import {
  applyOnboarding,
  createSightingKeyStore,
  keysDir,
  settingsDir,
  sightingKeyEndpointFingerprint,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { SIGHTING_SHARE_CONSENT_VERSION } from '@akasecurity/schema';

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

export const SIGHTING_TEST_ENDPOINT = 'https://plane.example.test';

/**
 * Stores `key` under `base` as issued by `issuedBy`. Unless `onboard` is false it
 * first attaches the machine to `attachedTo` with a usable credential, and
 * unless `sharing` is false it records the sighting-sharing grant for it.
 */
export function storeSightingKey(
  base: string,
  key: SightingKey,
  opts: { attachedTo?: string; issuedBy?: string; onboard?: boolean; sharing?: boolean } = {},
): void {
  const attachedTo = opts.attachedTo ?? SIGHTING_TEST_ENDPOINT;
  if (opts.onboard !== false) {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: attachedTo, attachedAt: '2026-10-01T00:00:00.000Z' },
      },
      base,
    );
    writeControlPlaneCredential(settingsDir(base), {
      specVersion: 1,
      endpoint: attachedTo,
      apiKey: 'placeholder',
      mintedAt: '2026-10-01T00:00:00.000Z',
    });
  }
  setSightingSharing(base, opts.sharing !== false, attachedTo);
  createSightingKeyStore('file', keysDir(base)).replace({
    keyVersion: key.keyVersion,
    algorithm: 'hmac-sha256',
    key: materialOf(key),
    fetchedAtMs: 1,
    endpointFingerprint: sightingKeyEndpointFingerprint(opts.issuedBy ?? attachedTo),
  });
}

/** Records or withdraws the sighting-sharing grant for `endpoint`. */
export function setSightingSharing(
  base: string,
  on: boolean,
  endpoint: string = SIGHTING_TEST_ENDPOINT,
): void {
  applyOnboarding(
    {
      sightingShareConsent: on
        ? {
            acknowledgedAt: '2026-10-01T00:00:00.000Z',
            version: SIGHTING_SHARE_CONSENT_VERSION,
            endpoint,
          }
        : undefined,
    },
    base,
  );
}
