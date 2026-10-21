import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { LocalDatabase, SightingKeys } from '@akasecurity/persistence';
import {
  applyOnboarding,
  createSightingKeyStore,
  DB_FILENAME,
  keysDir,
  openLocalDatabase,
  settingsDir,
  sightingKeyEndpointFingerprint,
  sightingToken,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { EgressIngestRequest, ManagedSettings, Rule } from '@akasecurity/schema';
import { EgressIngestRequest as RequestSchema } from '@akasecurity/schema';
import { SIGHTING_SHARE_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { encodeIndex } from '../../../test/helpers/git-index.ts';
import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { recordProjectEgress } from '../src/egress-record.ts';
import { scanPathIntoStore } from '../src/fs-scan.ts';
import type { SharesForwardSender } from '../src/shares-forward.ts';
import { forwardProjectEgress } from '../src/shares-forward.ts';
import { migratedStore } from './helpers/store-templates.ts';

// Assembled at runtime so no key-shaped literal or variable read sits in this file.
const INSIDE = ['AK', 'IA'].join('') + 'Q7'.repeat(8);
const OUTSIDE = ['AK', 'IA'].join('') + 'Z3'.repeat(8);
const ENV = ['process', 'env'].join('.');
const ENDPOINT = 'https://aka.acme.test';
const MINTED_AT = '2026-10-01T00:00:00.000Z';
const API_KEY = ['test', 'plugin', 'key'].join('-');
const REPO_URL = 'https://github.com/acme/widgets.git';
const STORED_KEY = {
  keyVersion: 2,
  algorithm: 'hmac-sha256' as const,
  key: Buffer.alloc(32, 9).toString('base64url'),
  fetchedAtMs: 1,
  endpointFingerprint: sightingKeyEndpointFingerprint(ENDPOINT),
};
// The same key, held independently of the custody read.
const KEY = { keyVersion: 2, key: new Uint8Array(Buffer.alloc(32, 9)) };
const KEYS: SightingKeys = { current: KEY, previous: [] };
const PREVIOUS_KEY = { keyVersion: 1, key: new Uint8Array(Buffer.alloc(32, 4)) };

const RULES: Rule[] = [
  {
    specVersion: 1,
    id: 'test/aws-key',
    name: 'AWS access key',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: 'AKIA[0-9A-Z]{16}', flags: 'g' },
  },
];

const SOURCE = [
  `const fallback = '${OUTSIDE}';`,
  `const other = ${ENV}.UNRELATED;`,
  `export const charge = () =>`,
  `  fetch('https://api.stripe.com/v1/charges', {`,
  `    method: 'POST',`,
  `    headers: { 'X-Literal': '${INSIDE}', 'X-Read': ${ENV}.STRIPE_SECRET_KEY },`,
  `  });`,
  '',
].join('\n');

let base: string;
let store: string;
let root: string;
let db: LocalDatabase;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-refs-home-'));
  store = join(base, 'data');
  mkdirSync(store);
  migratedStore.seed(store);
  root = mkdtempSync(join(tmpdir(), 'aka-refs-root-'));
  mkdirSync(join(root, '.git'));
  writeFileSync(join(root, '.git', 'index'), encodeIndex(['charge.ts']));
  writeFileSync(
    join(root, '.git', 'config'),
    `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${REPO_URL}\n`,
  );
  writeFileSync(join(root, 'charge.ts'), SOURCE);
  db = openLocalDatabase(store);
});

afterEach(() => {
  db.close();
  removeTrees([root, base]);
});

function attach(opts: { consent: boolean; key: boolean }): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: MINTED_AT },
      ...(opts.consent
        ? {
            sightingShareConsent: {
              acknowledgedAt: new Date().toISOString(),
              version: SIGHTING_SHARE_CONSENT_VERSION,
              endpoint: ENDPOINT,
            },
          }
        : {}),
    },
    base,
    null,
  );
  writeControlPlaneCredential(settingsDir(base), {
    specVersion: 1,
    endpoint: ENDPOINT,
    apiKey: API_KEY,
    mintedAt: MINTED_AT,
  });
  if (opts.key) createSightingKeyStore('file', keysDir(base)).replace(STORED_KEY);
}

const forbid = (value: boolean): ManagedSettings => ({
  specVersion: 1,
  values: { sightingShareConsent: value },
  lockedFields: [],
});

async function scanAndForward(
  sightingKeys: SightingKeys | undefined,
  managedSettings: ManagedSettings | null = null,
): Promise<EgressIngestRequest[]> {
  const result = await scanPathIntoStore(db, root, { rules: RULES, dataDir: store, sightingKeys });
  const recorded = recordProjectEgress(db, root, result.egress, base);
  expect(recorded).not.toBeNull();
  const requests: EgressIngestRequest[] = [];
  const send: SharesForwardSender = (_connection, request) => {
    requests.push(request);
    return Promise.resolve({ ok: true });
  };
  if (recorded !== null) {
    await forwardProjectEgress(base, recorded.input, {
      send,
      nestedRepositories: [],
      managedSettings,
    });
  }
  return requests;
}

describe('forwardProjectEgress credential references', () => {
  it('sends the literal as its token and the variable by name, for the call that uses them', async () => {
    attach({ consent: true, key: true });

    const [request] = await scanAndForward(KEYS);

    expect(request).toBeDefined();
    expect(RequestSchema.safeParse(request).success).toBe(true);
    const charge = request?.hits.find((h) => h.host === 'api.stripe.com');
    expect(charge?.credentialRefs).toEqual([
      { kind: 'literal', token: sightingToken(KEY, INSIDE), ruleId: 'test/aws-key' },
      { kind: 'variable', variableName: 'STRIPE_SECRET_KEY' },
    ]);
    const body = JSON.stringify(request);
    expect(body).not.toContain(INSIDE);
    expect(body).not.toContain(OUTSIDE);
    expect(body).not.toContain(sightingToken(KEY, OUTSIDE));
    expect(body).not.toContain('UNRELATED');
  });

  it('carries the literal under each previous key version still held as its aliases', async () => {
    attach({ consent: true, key: true });

    const [request] = await scanAndForward({ current: KEY, previous: [PREVIOUS_KEY] });

    expect(RequestSchema.safeParse(request).success).toBe(true);
    const charge = request?.hits.find((h) => h.host === 'api.stripe.com');
    expect(charge?.credentialRefs?.[0]).toEqual({
      kind: 'literal',
      token: sightingToken(KEY, INSIDE),
      aliases: [sightingToken(PREVIOUS_KEY, INSIDE)],
      ruleId: 'test/aws-key',
    });
    const body = JSON.stringify(request);
    expect(body).not.toContain(INSIDE);
    expect(body).not.toContain(OUTSIDE);
  });

  it('keeps no reference in the local register', async () => {
    attach({ consent: true, key: true });
    await scanAndForward(KEYS);

    const raw = new DatabaseSync(join(store, DB_FILENAME), { readOnly: true });
    try {
      const rows = ['share_destination', 'share_endpoint', 'share_call_site'].map((table) =>
        raw.prepare(`SELECT * FROM ${table}`).all(),
      );
      expect(rows[2]?.length).toBeGreaterThan(0);
      const local = JSON.stringify(rows);
      expect(local).not.toContain(INSIDE);
      expect(local).not.toContain(sightingToken(KEY, INSIDE));
    } finally {
      raw.close();
    }
  });

  it('sends none while this machine does not share sightings', async () => {
    attach({ consent: false, key: true });

    const [request] = await scanAndForward(KEYS);

    expect(request).toBeDefined();
    expect(request?.hits.every((h) => !('credentialRefs' in h))).toBe(true);
  });

  it('sends none when sharing is turned off between the scan and the forward', async () => {
    attach({ consent: true, key: true });

    const [request] = await scanAndForward(KEYS, forbid(false));

    expect(request?.hits.every((h) => !('credentialRefs' in h))).toBe(true);
  });

  it('sends none without a sighting key', async () => {
    attach({ consent: true, key: false });

    const [request] = await scanAndForward(undefined);

    expect(request).toBeDefined();
    expect(request?.hits.every((h) => !('credentialRefs' in h))).toBe(true);
  });

  it('sends nothing at all from a standalone machine', async () => {
    expect(await scanAndForward(KEYS)).toEqual([]);
  });
});
