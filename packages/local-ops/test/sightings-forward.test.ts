import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { CredentialSightingsSend, LocalDatabase } from '@akasecurity/persistence';
import {
  applyOnboarding,
  createSightingKeyStore,
  hashProjectKey,
  keysDir,
  openLocalDatabase,
  settingsDir,
  sightingKeyEndpointFingerprint,
  sightingToken,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { CredentialSightingsRequest, Rule } from '@akasecurity/schema';
import { SIGHTING_SHARE_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { encodeIndex } from '../../../test/helpers/git-index.ts';
import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { scanPathIntoStore } from '../src/fs-scan.ts';
import { forwardScanSightings } from '../src/sightings-forward.ts';
import { migratedStore } from './helpers/store-templates.ts';

// Assembled at runtime so no key-shaped literal sits in this file.
const VALUE = ['AK', 'IA'].join('') + 'Q7'.repeat(8);
const OTHER_VALUE = ['AK', 'IA'].join('') + 'Z3'.repeat(8);
const ENDPOINT = 'https://aka.acme.test';
const MINTED_AT = '2026-10-01T00:00:00.000Z';
const API_KEY = ['test', 'plugin', 'key'].join('-');
const WORK_URL = 'https://github.com/acme/widgets.git';
const WORK_KEY = 'github.com/acme/widgets';
const PERSONAL_URL = 'https://github.com/someone/tools.git';
const STORED_KEY = {
  keyVersion: 2,
  algorithm: 'hmac-sha256' as const,
  key: Buffer.alloc(32, 9).toString('base64url'),
  fetchedAtMs: 1,
  endpointFingerprint: sightingKeyEndpointFingerprint(ENDPOINT),
};
// The same key, held independently of the custody read.
const KEY = { keyVersion: 2, key: new Uint8Array(Buffer.alloc(32, 9)) };

const RULES: Rule[] = [
  {
    specVersion: 1,
    id: 'test/aws-key',
    name: 'AWS access key',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: 'AKIA[0-9A-Z]{16}', flags: 'g' },
  },
  {
    specVersion: 1,
    id: 'test/email',
    name: 'Email',
    category: 'pii',
    severity: 'low',
    matcher: { type: 'regex', pattern: '[a-z]+@example\\.org', flags: 'g' },
  },
];

let base: string;
let store: string;
let root: string;
let db: LocalDatabase;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-sightings-home-'));
  store = join(base, 'data');
  mkdirSync(store);
  migratedStore.seed(store);
  root = mkdtempSync(join(tmpdir(), 'aka-sightings-root-'));
  db = openLocalDatabase(store);
});

afterEach(() => {
  db.close();
  removeTrees([root, base]);
});

function gitRepo(dir: string, url?: string, tracked: string[] = []): void {
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(join(dir, '.git', 'index'), encodeIndex(tracked));
  const remote = url === undefined ? '' : `[remote "origin"]\n\turl = ${url}\n`;
  writeFileSync(join(dir, '.git', 'config'), `[core]\n\tbare = false\n${remote}`);
}

function sharingAttachment(mode: 'machine' | 'scoped', enrolled: string[] = []): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: MINTED_AT },
      sightingShareConsent: {
        acknowledgedAt: new Date().toISOString(),
        version: SIGHTING_SHARE_CONSENT_VERSION,
        endpoint: ENDPOINT,
      },
      ...(mode === 'scoped'
        ? {
            attachmentScope: {
              endpoint: ENDPOINT,
              entries: enrolled.map((identity) => ({
                kind: 'repo' as const,
                identity,
                enrolledAt: MINTED_AT,
              })),
            },
          }
        : {}),
    },
    base,
    null,
  );
  writeControlPlaneCredential(
    settingsDir(base),
    mode === 'machine'
      ? { specVersion: 1, endpoint: ENDPOINT, apiKey: API_KEY, mintedAt: MINTED_AT }
      : {
          specVersion: 2,
          mode: 'scoped',
          endpoint: ENDPOINT,
          apiKey: API_KEY,
          mintedAt: MINTED_AT,
        },
  );
  createSightingKeyStore('file', keysDir(base)).replace(STORED_KEY);
}

function recorder(): { send: CredentialSightingsSend; requests: CredentialSightingsRequest[] } {
  const requests: CredentialSightingsRequest[] = [];
  return {
    requests,
    send: (_connection, request) => {
      requests.push(request);
      return Promise.resolve({ ok: true, accepted: request.sightings.length });
    },
  };
}

const scan = (sightingKey = KEY) =>
  scanPathIntoStore(db, root, { rules: RULES, dataDir: store, sightingKey });

describe('scanPathIntoStore — sighting tokens', () => {
  it('reduces each secret it finds to its token, and carries no value', async () => {
    writeFileSync(join(root, 'config.ts'), `const AWS_ACCESS_KEY_ID = '${VALUE}';\n`);
    writeFileSync(join(root, 'notes.txt'), ['mail jane', 'example.org'].join('@') + '\n');

    const result = await scan();

    expect(result.sightings).toEqual([
      {
        token: sightingToken(KEY, VALUE),
        ruleId: 'test/aws-key',
        variableName: 'AWS_ACCESS_KEY_ID',
        file: join(root, 'config.ts'),
      },
    ]);
    expect(JSON.stringify(result.sightings)).not.toContain(VALUE);
  });

  it('computes no token without a key', async () => {
    writeFileSync(join(root, 'config.ts'), `const AWS_ACCESS_KEY_ID = '${VALUE}';\n`);

    const result = await scanPathIntoStore(db, root, { rules: RULES, dataDir: store });

    expect(result.sightings).toEqual([]);
  });
});

describe('forwardScanSightings', () => {
  it('sends the tokens of a git project under its Data Shares identity', async () => {
    gitRepo(root, WORK_URL, ['config.ts', '.gitignore']);
    writeFileSync(join(root, 'config.ts'), `const AWS_ACCESS_KEY_ID = '${VALUE}';\n`);
    mkdirSync(join(root, '.github'));
    writeFileSync(join(root, '.github', 'ci.yml'), `token: ${OTHER_VALUE}\n`);
    writeFileSync(join(root, '.gitignore'), 'local.env\n');
    writeFileSync(join(root, 'local.env'), `AWS_KEY=${VALUE}\n`);
    sharingAttachment('machine');
    const rec = recorder();

    const result = await scan();
    const outcome = await forwardScanSightings(base, root, result, {
      send: rec.send,
      managedSettings: null,
    });

    expect(outcome).toEqual({ status: 'sent', shared: 2, keptLocal: 0, unsent: 0 });
    const sent = rec.requests.flatMap((r) => r.sightings);
    const project = { projectKey: hashProjectKey(`git:${WORK_URL}`), name: 'widgets' };
    expect(sent).toHaveLength(2);
    expect(sent).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          token: sightingToken(KEY, OTHER_VALUE),
          locationClass: 'project-dot-directory',
          project,
          gitTracked: false,
        }),
        expect.objectContaining({
          token: sightingToken(KEY, VALUE),
          locationClass: 'project-file',
          project,
          gitTracked: true,
          variableName: 'AWS_ACCESS_KEY_ID',
        }),
      ]),
    );
    const wire = JSON.stringify(rec.requests);
    for (const forbidden of [VALUE, OTHER_VALUE, root, 'config.ts', 'ci.yml', 'local.env']) {
      expect(wire).not.toContain(forbidden);
    }
  });

  it('keeps a nested repository a scoped attachment does not enroll', async () => {
    gitRepo(root, WORK_URL);
    const mine = join(root, 'tools', 'mine');
    gitRepo(mine, PERSONAL_URL);
    writeFileSync(join(root, 'config.ts'), `const AWS_ACCESS_KEY_ID = '${VALUE}';\n`);
    writeFileSync(join(mine, 'a.ts'), `const K = '${OTHER_VALUE}';\n`);
    sharingAttachment('scoped', [WORK_KEY]);
    const rec = recorder();

    const result = await scan();
    const outcome = await forwardScanSightings(base, root, result, {
      send: rec.send,
      managedSettings: null,
    });

    expect(outcome).toEqual({ status: 'sent', shared: 1, keptLocal: 1, unsent: 0 });
    expect(rec.requests.flatMap((r) => r.sightings.map((s) => s.token))).toEqual([
      sightingToken(KEY, VALUE),
    ]);
  });

  it('marks nothing tracked outside a git working tree, under the hashed path key', async () => {
    writeFileSync(join(root, 'config.ts'), `const AWS_ACCESS_KEY_ID = '${VALUE}';\n`);
    sharingAttachment('machine');
    const rec = recorder();

    const result = await scan();
    await forwardScanSightings(base, root, result, { send: rec.send, managedSettings: null });

    const [sighting] = rec.requests.flatMap((r) => r.sightings);
    expect(sighting?.gitTracked).toBe(false);
    expect(sighting?.project.projectKey).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(rec.requests)).not.toContain(root);
  });

  it('sends nothing when the machine does not share', async () => {
    writeFileSync(join(root, 'config.ts'), `const AWS_ACCESS_KEY_ID = '${VALUE}';\n`);
    const rec = recorder();

    const result = await scan();
    const outcome = await forwardScanSightings(base, root, result, {
      send: rec.send,
      managedSettings: null,
    });

    expect(outcome).toMatchObject({ status: 'not-shared', reason: 'sharing-off' });
    expect(rec.requests).toEqual([]);
  });

  it('answers a sender that throws without throwing', async () => {
    writeFileSync(join(root, 'config.ts'), `const AWS_ACCESS_KEY_ID = '${VALUE}';\n`);
    sharingAttachment('machine');

    const result = await scan();
    const outcome = await forwardScanSightings(base, root, result, {
      send: () => Promise.reject(new Error('socket hang up')),
      managedSettings: null,
    });

    expect(outcome).toMatchObject({ status: 'sent', shared: 0, failure: 'unreachable' });
  });
});
