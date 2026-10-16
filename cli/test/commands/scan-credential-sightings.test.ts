import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

import type { CredentialSightingsSend } from '@akasecurity/persistence';
import {
  applyOnboarding,
  createSightingKeyStore,
  hashProjectKey,
  keysDir,
  settingsDir,
  sightingKeyEndpointFingerprint,
  sightingToken,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { dataDir } from '@akasecurity/plugin-sdk';
import type { CredentialSightingsRequest } from '@akasecurity/schema';
import {
  CredentialSightingsRequest as RequestSchema,
  SIGHTING_SHARE_CONSENT_VERSION,
  SIGHTING_SHARE_PAYLOAD_NOTE,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { runScan } from '../../src/commands/scan.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// Assembled at runtime so no key-shaped literal sits in this file.
const VALUE = ['AK', 'IA'].join('') + ['R7XM', '2QTB', '9KZP', '4HWN'].join('');
const ENDPOINT = 'https://cp.example';
const MINTED_AT = '2026-10-01T00:00:00.000Z';
const API_KEY = ['test', 'plugin', 'key'].join('-');
const KEY_BYTES = Buffer.alloc(32, 5);
const INDEPENDENT_KEY = { keyVersion: 7, key: new Uint8Array(KEY_BYTES) };

let home: string;
let root: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-scan-sightings-home-'));
  root = mkdtempSync(join(tmpdir(), 'aka-scan-sightings-root-'));
  mkdirSync(dataDir(home), { recursive: true });
  migratedStore.seed(dataDir(home));
  writeFileSync(join(root, 'deploy.ts'), `export const AWS_ACCESS_KEY_ID = '${VALUE}';\n`);
});

afterEach(() => {
  vi.restoreAllMocks();
  removeTrees([home, root]);
  process.exitCode = undefined;
});

function sharingMachine(): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: MINTED_AT },
      sightingShareConsent: {
        acknowledgedAt: new Date().toISOString(),
        version: SIGHTING_SHARE_CONSENT_VERSION,
        endpoint: ENDPOINT,
      },
    },
    home,
    null,
  );
  writeControlPlaneCredential(settingsDir(home), {
    specVersion: 1,
    endpoint: ENDPOINT,
    apiKey: API_KEY,
    mintedAt: MINTED_AT,
  });
  createSightingKeyStore('file', keysDir(home)).replace({
    keyVersion: 7,
    algorithm: 'hmac-sha256',
    key: KEY_BYTES.toString('base64url'),
    fetchedAtMs: Date.now(),
    endpointFingerprint: sightingKeyEndpointFingerprint(ENDPOINT),
  });
}

function recorder(fail = false): {
  send: CredentialSightingsSend;
  requests: CredentialSightingsRequest[];
} {
  const requests: CredentialSightingsRequest[] = [];
  return {
    requests,
    send: (_connection, request) => {
      requests.push(request);
      return Promise.resolve(
        fail
          ? { ok: false, kind: 'unreachable' }
          : { ok: true, accepted: request.sightings.length },
      );
    },
  };
}

async function scan(args: string[], sendSightings: CredentialSightingsSend): Promise<string> {
  let out = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
    out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  await runScan([root, '--home', home, ...args], {
    managedSettings: null,
    send: () => Promise.resolve({ ok: true }),
    sendSightings,
  });
  vi.restoreAllMocks();
  return out;
}

describe('aka scan — credential sightings', () => {
  it('sends each secret as its token and nothing derived from the value but the token', async () => {
    sharingMachine();
    const rec = recorder();

    const out = await scan([], rec.send);

    expect(rec.requests).toHaveLength(1);
    const request = rec.requests[0];
    expect(RequestSchema.parse(request)).toEqual(request);
    expect(request?.sightings).toEqual([
      {
        token: sightingToken(INDEPENDENT_KEY, VALUE),
        ruleId: expect.any(String) as string,
        category: 'secret',
        variableName: 'AWS_ACCESS_KEY_ID',
        locationClass: 'project-file',
        project: {
          projectKey: hashProjectKey(`path:${realpathSync(root)}`),
          name: basename(realpathSync(root)),
        },
        gitTracked: false,
        seenAt: expect.any(String) as string,
      },
    ]);
    const wire = JSON.stringify(rec.requests);
    expectNoEchoOf(wire, VALUE);
    for (const forbidden of [root, 'deploy.ts', VALUE.slice(0, 4) + '*']) {
      expect(wire).not.toContain(forbidden);
    }
    expect(out.trimEnd().split('\n').at(-1)).toBe(
      `Credential sightings: 1 shared with your organization. ${SIGHTING_SHARE_PAYLOAD_NOTE}`,
    );
  });

  it('sends in JSON mode too, without adding to the payload', async () => {
    sharingMachine();
    const rec = recorder();

    const out = await scan(['--format', 'json'], rec.send);

    expect(rec.requests).toHaveLength(1);
    expect(out).not.toContain('Credential sightings');
    expect(Object.keys(JSON.parse(out) as object)).not.toContain('sightings');
  });

  it('keeps the scan whole and says so when the send fails', async () => {
    sharingMachine();
    const rec = recorder(true);

    const out = await scan([], rec.send);

    expect(process.exitCode).toBeUndefined();
    expect(out).toMatch(/Scanned \d+ file\(s\)/);
    expect(out.trimEnd().split('\n').at(-1)).toBe(
      'Credential sightings: not shared — control plane unreachable; the next scan sends them ' +
        `again. ${SIGHTING_SHARE_PAYLOAD_NOTE}`,
    );
  });

  it('sends nothing from a standalone machine', async () => {
    const rec = recorder();

    const out = await scan([], rec.send);

    expect(rec.requests).toEqual([]);
    expect(out.trimEnd().split('\n').at(-1)).toContain('Credential sightings: off (standalone)');
  });

  it('sends nothing for a --no-forward run', async () => {
    sharingMachine();
    const rec = recorder();

    await scan(['--no-forward'], rec.send);

    expect(rec.requests).toEqual([]);
  });
});
