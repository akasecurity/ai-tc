/**
 * `/aka:scan` on a machine that shares credential sightings tries to send the
 * secret a dotenv file holds, and says what happened in its last line. Drives
 * the BUILT `scripts/filescan.js` against a throwaway home attached to a port
 * nothing listens on, so the send is refused at once; what the request carries
 * is pinned in the scanner's own suite.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  applyOnboarding,
  createSightingKeyStore,
  keysDir,
  settingsDir,
  sightingKeyEndpointFingerprint,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { SIGHTING_SHARE_CONSENT_VERSION, SIGHTING_SHARE_PAYLOAD_NOTE } from '@akasecurity/schema';
import { afterAll, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { hostEnv, tempHomeEnv } from '../helpers/run-hook.ts';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'filescan.js');
const CLOSED_ENDPOINT = 'http://localhost:1';
// Assembled at runtime so no key-shaped literal sits in this file.
const VALUE = ['AK', 'IA'].join('') + ['T4QW', '8NZX', '3LKP', '7VBM'].join('');

const temps: string[] = [];

afterAll(() => {
  removeTrees(temps);
});

describe('/aka:scan credential sightings', () => {
  it('tries to send a dotenv secret and reports the outcome in the footer', () => {
    const home = mkdtempSync(join(tmpdir(), 'aka-filescan-sightings-home-'));
    const target = mkdtempSync(join(tmpdir(), 'aka-filescan-sightings-target-'));
    temps.push(home, target);
    const base = join(home, '.aka');
    const attachedAt = '2026-10-01T00:00:00.000Z';
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: CLOSED_ENDPOINT, attachedAt },
        sightingShareConsent: {
          acknowledgedAt: new Date().toISOString(),
          version: SIGHTING_SHARE_CONSENT_VERSION,
          endpoint: CLOSED_ENDPOINT,
        },
      },
      base,
      null,
    );
    writeControlPlaneCredential(settingsDir(base), {
      specVersion: 1,
      endpoint: CLOSED_ENDPOINT,
      apiKey: ['test', 'plugin', 'key'].join('-'),
      mintedAt: attachedAt,
    });
    createSightingKeyStore('file', keysDir(base)).replace({
      keyVersion: 2,
      algorithm: 'hmac-sha256',
      key: Buffer.alloc(32, 8).toString('base64url'),
      fetchedAtMs: Date.now(),
      endpointFingerprint: sightingKeyEndpointFingerprint(CLOSED_ENDPOINT),
    });
    writeFileSync(join(target, '.env'), `AWS_ACCESS_KEY_ID=${VALUE}\n`);

    const result = spawnSync(process.execPath, [SCRIPT, '--dir', target], {
      encoding: 'utf8',
      env: { ...hostEnv(), ...tempHomeEnv(home) },
      timeout: 60_000,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).not.toContain(VALUE);
    const lines = result.stdout.trimEnd().split('\n');
    expect(lines.at(-2)).toBe(
      '  Credential sightings: not shared — control plane unreachable; the next scan sends ' +
        `them again. ${SIGHTING_SHARE_PAYLOAD_NOTE}`,
    );
  });
});
