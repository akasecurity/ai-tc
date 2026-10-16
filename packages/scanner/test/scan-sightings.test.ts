import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { CredentialSightingsSend } from '@akasecurity/plugin-runtime';
import {
  setDefaultGatewayFactory,
  sightingToken,
  standaloneGatewayFactory,
} from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { applyOnboarding, loadConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { encodeIndex } from '../../../test/helpers/git-index.ts';
import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { scanAllRepos, scanWorktree } from '../src/scan.ts';

// Assembled at runtime so no key-shaped literal sits in this file.
const SOURCE_VALUE = ['AK', 'IA'].join('') + ['R7XM', '2QTB', '9KZP', '4HWN'].join('');
const DOTENV_VALUE = ['AK', 'IA'].join('') + ['T4QW', '8NZX', '3LKP', '7VBM'].join('');
const ENDPOINT = 'https://cp.example';
const MINTED_AT = '2026-10-01T00:00:00.000Z';
const KEY_BYTES = Buffer.alloc(32, 6);
const KEY = { keyVersion: 3, key: new Uint8Array(KEY_BYTES) };
const REMOTE = 'https://github.com/acme/widgets.git';

interface SentRequest {
  sightings: {
    token: string;
    locationClass: string;
    variableName?: string | undefined;
    gitTracked: boolean;
    project: { projectKey: string; name: string };
  }[];
}

let home: string;
let repo: string;
let restoreGateway: () => void;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-scan-sightings-home-'));
  repo = mkdtempSync(join(tmpdir(), 'aka-scan-sightings-repo-'));
  mkdirSync(join(repo, '.git'));
  writeFileSync(
    join(repo, '.git', 'config'),
    `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${REMOTE}\n`,
  );
  writeFileSync(join(repo, 'deploy.ts'), `export const AWS_ACCESS_KEY_ID = '${SOURCE_VALUE}';\n`);
  writeFileSync(join(repo, '.env'), `AWS_ACCESS_KEY_ID=${DOTENV_VALUE}\n`);
  writeFileSync(join(repo, '.gitignore'), '.env\n');
  writeFileSync(join(repo, '.git', 'index'), encodeIndex(['.gitignore', 'deploy.ts']));
  // The attached gateway would forward each capture; these cases are about the
  // sightings route alone.
  restoreGateway = setDefaultGatewayFactory(standaloneGatewayFactory);
});

afterEach(() => {
  restoreGateway();
  removeTrees([home, repo]);
});

// `enrolled` makes the attachment scoped, enrolling those repositories.
function attach(consent: boolean, endpoint = ENDPOINT, enrolled?: string[]): PluginConfig {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint, attachedAt: MINTED_AT },
      ...(enrolled === undefined
        ? {}
        : {
            attachmentScope: {
              endpoint,
              entries: enrolled.map((identity) => ({
                kind: 'repo' as const,
                identity,
                enrolledAt: MINTED_AT,
              })),
            },
          }),
      ...(consent
        ? {
            sightingShareConsent: {
              acknowledgedAt: new Date().toISOString(),
              version: 2,
              endpoint,
            },
          }
        : {}),
    },
    home,
    null,
  );
  writeFileSync(
    join(home, 'settings', 'control-plane-credential.json'),
    JSON.stringify({
      ...(enrolled === undefined ? { specVersion: 1 } : { specVersion: 2, mode: 'scoped' }),
      endpoint,
      apiKey: ['test', 'plugin', 'key'].join('-'),
      mintedAt: MINTED_AT,
    }),
    { mode: 0o600 },
  );
  mkdirSync(join(home, 'keys'), { recursive: true });
  writeFileSync(
    join(home, 'keys', 'sighting.key'),
    JSON.stringify({
      keyVersion: 3,
      algorithm: 'hmac-sha256',
      key: KEY_BYTES.toString('base64url'),
      fetchedAtMs: Date.now(),
      endpointFingerprint: createHash('sha256').update(endpoint).digest('hex'),
    }),
    { mode: 0o600 },
  );
  return loadConfig(home);
}

function recorder(fail = false): { send: CredentialSightingsSend; requests: SentRequest[] } {
  const requests: SentRequest[] = [];
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

const options = (send: CredentialSightingsSend) => ({
  rootDir: repo,
  sourceTool: 'claude-code' as const,
  sendSightings: send,
  managedSettings: null,
});

describe('scanWorktree — credential sightings', () => {
  it('sends a source file and a dotenv file as tokens, and sends nothing of the dotenv file', async () => {
    const config = attach(true);
    const rec = recorder();

    const summary = await scanWorktree(config, options(rec.send));

    expect(summary.sightings).toEqual({ status: 'sent', shared: 2, keptLocal: 0, unsent: 0 });
    const sent = rec.requests.flatMap((r) => r.sightings);
    expect(sent).toHaveLength(2);
    expect(sent).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          token: sightingToken(KEY, SOURCE_VALUE),
          locationClass: 'project-file',
          variableName: 'AWS_ACCESS_KEY_ID',
          gitTracked: true,
        }),
        expect.objectContaining({
          token: sightingToken(KEY, DOTENV_VALUE),
          locationClass: 'project-file',
          gitTracked: false,
        }),
      ]),
    );
    const wire = JSON.stringify(rec.requests);
    for (const forbidden of [SOURCE_VALUE, DOTENV_VALUE, repo, 'deploy.ts', '.env']) {
      expect(wire).not.toContain(forbidden);
    }
  });

  it('reads an unchanged file again after a failed send, and not after a delivered one', async () => {
    const config = attach(true);
    const failing = recorder(true);

    const first = await scanWorktree(config, options(failing.send));
    expect(first.sightings).toMatchObject({ status: 'sent', shared: 0, failure: 'unreachable' });

    const delivered = recorder();
    await scanWorktree(config, options(delivered.send));
    expect(delivered.requests.flatMap((r) => r.sightings.map((s) => s.token))).toContain(
      sightingToken(KEY, SOURCE_VALUE),
    );

    expect(delivered.requests.flatMap((r) => r.sightings.map((s) => s.token))).toContain(
      sightingToken(KEY, DOTENV_VALUE),
    );

    const again = recorder();
    await scanWorktree(config, options(again.send));
    expect(again.requests.flatMap((r) => r.sightings.map((s) => s.token))).toEqual([]);
  });

  it('reads an unenrolled repository once, and again once it is enrolled', async () => {
    const kept = recorder();
    const first = await scanWorktree(attach(true, ENDPOINT, []), options(kept.send));
    expect(first.sightings).toMatchObject({ status: 'sent', shared: 0, unsent: 0 });
    expect(kept.requests).toEqual([]);

    const unchanged = await scanWorktree(attach(true, ENDPOINT, []), options(recorder().send));
    expect(unchanged.scanned).toBe(0);

    const enrolled = recorder();
    await scanWorktree(attach(true, ENDPOINT, ['github.com/acme/widgets']), options(enrolled.send));
    expect(enrolled.requests.flatMap((r) => r.sightings.map((s) => s.token))).toEqual(
      expect.arrayContaining([sightingToken(KEY, SOURCE_VALUE), sightingToken(KEY, DOTENV_VALUE)]),
    );
  });

  it('reads unchanged files again once attached to another deployment', async () => {
    await scanWorktree(attach(true), options(recorder().send));

    const elsewhere = recorder();
    await scanWorktree(attach(true, 'https://other.example'), options(elsewhere.send));
    expect(elsewhere.requests.flatMap((r) => r.sightings.map((s) => s.token))).toEqual(
      expect.arrayContaining([sightingToken(KEY, SOURCE_VALUE), sightingToken(KEY, DOTENV_VALUE)]),
    );
  });

  it('reads files scanned before sharing was on once it is on', async () => {
    const before = recorder();
    await scanWorktree(attach(false), options(before.send));
    expect(before.requests).toEqual([]);

    const after = recorder();
    await scanWorktree(attach(true), options(after.send));
    expect(after.requests.flatMap((r) => r.sightings.map((s) => s.token))).toContain(
      sightingToken(KEY, SOURCE_VALUE),
    );
  });

  it('sends nothing on a machine that does not share', async () => {
    const config = attach(false);
    const rec = recorder();

    const summary = await scanWorktree(config, options(rec.send));

    expect(rec.requests).toEqual([]);
    expect(summary.sightings).toMatchObject({ status: 'not-shared', reason: 'sharing-off' });
  });

  it('sends nothing from a standalone machine', async () => {
    const config = loadConfig(home);
    const rec = recorder();

    const summary = await scanWorktree(config, options(rec.send));

    expect(rec.requests).toEqual([]);
    expect(summary.sightings).toMatchObject({
      status: 'not-shared',
      reason: 'sharing-off',
      sharing: { mode: 'standalone' },
    });
  });
});

describe('scanAllRepos — credential sightings', () => {
  it('sums what each repository shared', async () => {
    const config = attach(true);
    const rec = recorder();

    const summary = await scanAllRepos(config, {
      ...options(rec.send),
      searchRoots: [repo],
    });

    expect(summary.sightings).toEqual({ status: 'sent', shared: 2, keptLocal: 0, unsent: 0 });
  });

  it('reports why nothing was shared when the machine does not share', async () => {
    const rec = recorder();
    const summary = await scanAllRepos(loadConfig(home), {
      ...options(rec.send),
      searchRoots: [repo],
    });
    expect(summary.sightings).toMatchObject({ status: 'not-shared', reason: 'sharing-off' });
  });
});
