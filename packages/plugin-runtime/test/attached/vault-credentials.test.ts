import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { useLoopbackServer } from '../../../remote/test/helpers/loopback.ts';
import {
  listAvailableCredentials,
  resolveCredentialValues,
} from '../../src/attached/vault-credentials.ts';

const server = useLoopbackServer();
const VALUE = 'vault-value-7c1e9a0b3d5f';
let base: string;
let dataDir: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-vault-credentials-'));
  dataDir = dataDirOf(base);
  mkdirSync(dataDir, { recursive: true });
});
afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

function attachTo(respond: (url: string) => { status: number; body: unknown } | null): string[] {
  const seen: string[] = [];
  server.reply((req, res) => {
    seen.push(`${req.method ?? ''} ${req.url ?? ''}`);
    const answer = respond(req.url ?? '');
    if (answer === null) return;
    res.writeHead(answer.status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(answer.body));
  });
  const endpoint = server.origin;
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint, attachedAt: '2026-11-17T10:00:00.000Z' } },
    base,
  );
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: 1,
    endpoint,
    apiKey: 'not-a-real-key-vault',
  });
  return seen;
}

/** Every file under the AKA home, read whole, so a test can assert a value reached none of them. */
function everyFileText(dir: string): string {
  let text = '';
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    text += statSync(path).isDirectory() ? everyFileText(path) : readFileSync(path, 'latin1');
  }
  return text;
}

describe('listAvailableCredentials', () => {
  it('returns the credentials the deployment grants this machine', async () => {
    const seen = attachTo(() => ({
      status: 200,
      body: { credentials: [{ slug: 'github', description: 'GitHub token' }] },
    }));
    await expect(listAvailableCredentials({ dataDir })).resolves.toEqual([
      { slug: 'github', description: 'GitHub token' },
    ]);
    expect(seen).toEqual(['GET /v1/vault/available']);
  });

  it('is undefined on a machine that is not attached', async () => {
    await expect(listAvailableCredentials({ dataDir })).resolves.toBeUndefined();
  });

  it('is undefined on an older deployment, an error and an unreadable answer', async () => {
    for (const answer of [
      { status: 404, body: {} },
      { status: 500, body: {} },
      { status: 200, body: { credentials: 'none' } },
    ]) {
      attachTo(() => answer);
      await expect(listAvailableCredentials({ dataDir })).resolves.toBeUndefined();
    }
  });

  it('is undefined when the deployment does not answer in time', async () => {
    attachTo(() => null);
    await expect(listAvailableCredentials({ dataDir, timeoutMs: 100 })).resolves.toBeUndefined();
  });
});

describe('resolveCredentialValues', () => {
  it('asks for each slug once and returns values and refusals', async () => {
    const seen = attachTo(() => ({
      status: 200,
      body: {
        resolved: [{ slug: 'github', value: VALUE }],
        refused: [{ slug: 'stripe', reason: 'no_grant' }],
      },
    }));
    const answer = await resolveCredentialValues({
      dataDir,
      slugs: ['github', 'stripe', 'github'],
      sessionId: 'session-1',
    });
    expect(answer).toEqual({
      resolved: [{ slug: 'github', value: VALUE }],
      refused: [{ slug: 'stripe', reason: 'no_grant' }],
    });
    expect(seen).toEqual(['POST /v1/vault/resolve']);
  });

  it('writes no value anywhere under the AKA home', async () => {
    attachTo(() => ({
      status: 200,
      body: { resolved: [{ slug: 'github', value: VALUE }], refused: [] },
    }));
    const before = everyFileText(base);
    expect(before).toContain('not-a-real-key-vault');
    await resolveCredentialValues({ dataDir, slugs: ['github'], sessionId: 's' });
    expect(everyFileText(base)).not.toContain(VALUE);
  });

  it('asks nothing for no slugs or on a machine that is not attached', async () => {
    await expect(
      resolveCredentialValues({ dataDir, slugs: ['github'], sessionId: 's' }),
    ).resolves.toBeUndefined();
    const seen = attachTo(() => ({ status: 200, body: { resolved: [], refused: [] } }));
    await expect(
      resolveCredentialValues({ dataDir, slugs: [], sessionId: 's' }),
    ).resolves.toBeUndefined();
    expect(seen).toEqual([]);
  });

  it('is undefined on a failure or a timeout', async () => {
    attachTo(() => ({ status: 503, body: {} }));
    await expect(
      resolveCredentialValues({ dataDir, slugs: ['github'], sessionId: undefined }),
    ).resolves.toBeUndefined();
    attachTo(() => null);
    await expect(
      resolveCredentialValues({ dataDir, slugs: ['github'], sessionId: 's', timeoutMs: 100 }),
    ).resolves.toBeUndefined();
  });
});
