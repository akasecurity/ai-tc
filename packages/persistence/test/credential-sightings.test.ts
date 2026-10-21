import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type {
  AttachedCredentialAny,
  CredentialSightingsRequest,
  RemoteFailureKind,
} from '@akasecurity/schema';
import { CredentialSightingsRequest as RequestSchema } from '@akasecurity/schema';
import { SIGHTING_SHARE_CONSENT_VERSION } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { writeGitRepo } from '../../../test/helpers/git-index.ts';
import { writeControlPlaneCredential } from '../src/control-plane-credential.ts';
import type {
  CredentialSightingsSend,
  ScanSighting,
  SightingScanProject,
} from '../src/credential-sightings.ts';
import {
  forwardCredentialSightings,
  planSightingShare,
  sightingLocationClass,
} from '../src/credential-sightings.ts';
import { hashProjectKey } from '../src/egress-wire.ts';
import { keysDir } from '../src/local-layout.ts';
import { applyOnboarding } from '../src/settings.ts';
import {
  createSightingKeyStore,
  sightingKeyEndpointFingerprint,
  sightingKeysOf,
} from '../src/vault/sighting-keys.ts';
import { sightingToken } from '../src/vault/sighting-token.ts';
import { expectNoEchoOf } from './helpers/no-echo.ts';
import { useTempStore } from './helpers/temp-store.ts';

const store = useTempStore('aka-credential-sightings-');

const ENDPOINT = 'https://cp.example';
const MINTED_AT = '2026-10-01T00:00:00.000Z';
const CREDENTIAL_VALUE = ['plugin', 'credential'].join('-');
const KEY_BYTES = Buffer.alloc(32, 11);
const STORED_KEY = {
  keyVersion: 4,
  algorithm: 'hmac-sha256' as const,
  key: KEY_BYTES.toString('base64url'),
  fetchedAtMs: 1,
  endpointFingerprint: sightingKeyEndpointFingerprint(ENDPOINT),
};
const REPO_URL = 'https://github.com/acme/widgets.git';
const REPO_KEY = 'github.com/acme/widgets';
// Values assembled at runtime so none sits in this file as a literal.
const VALUE_A = ['AK', 'IA', 'Q7RT', '2MXP', '9KZB', '4HWN'].join('');
const VALUE_B = ['gh', 'p_', 'x'.repeat(36)].join('');

// Directories inside the harness's own tree, so its teardown removes them.
let made = 0;
function tempDir(prefix: string): string {
  made += 1;
  const dir = join(store.home, 'trees', `${prefix}${String(made)}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function attach(mode: 'machine' | 'scoped', scope: string[] = []): void {
  const minted: AttachedCredentialAny =
    mode === 'machine'
      ? { specVersion: 1, endpoint: ENDPOINT, apiKey: CREDENTIAL_VALUE, mintedAt: MINTED_AT }
      : {
          specVersion: 2,
          mode: 'scoped',
          endpoint: ENDPOINT,
          apiKey: CREDENTIAL_VALUE,
          mintedAt: MINTED_AT,
        };
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: MINTED_AT },
      ...(mode === 'scoped'
        ? {
            attachmentScope: {
              endpoint: ENDPOINT,
              entries: scope.map((identity) => ({ kind: 'repo', identity, enrolledAt: MINTED_AT })),
            },
          }
        : {}),
    },
    store.home,
    null,
  );
  writeControlPlaneCredential(store.settingsDir, minted);
}

function consent(): void {
  applyOnboarding(
    {
      sightingShareConsent: {
        acknowledgedAt: new Date().toISOString(),
        version: SIGHTING_SHARE_CONSENT_VERSION,
        endpoint: ENDPOINT,
      },
    },
    store.home,
    null,
  );
}

function holdKey(): void {
  createSightingKeyStore('file', keysDir(store.home)).replace(STORED_KEY);
}

const independentKey = sightingKeysOf(STORED_KEY, 0).current;

interface Recorder {
  send: CredentialSightingsSend;
  requests: CredentialSightingsRequest[];
  connections: { endpoint: string; apiKey: string }[];
}

function recorder(
  answer: (n: number) => RemoteFailureKind | undefined = () => undefined,
): Recorder {
  const requests: CredentialSightingsRequest[] = [];
  const connections: { endpoint: string; apiKey: string }[] = [];
  return {
    requests,
    connections,
    send: (connection, request) => {
      connections.push(connection);
      requests.push(request);
      const failure = answer(requests.length);
      return Promise.resolve(
        failure === undefined
          ? { ok: true, accepted: request.sightings.length }
          : { ok: false, kind: failure },
      );
    },
  };
}

function project(root: string, overrides: Partial<SightingScanProject> = {}): SightingScanProject {
  return { projectKey: `git:${REPO_URL}`, name: 'acme/widgets', root, ...overrides };
}

function sightingIn(file: string, value: string, overrides: Partial<ScanSighting> = {}) {
  return {
    token: sightingToken(independentKey, value),
    ruleId: 'aws-access-key',
    variableName: 'AWS_ACCESS_KEY_ID',
    file,
    scopeKey: REPO_KEY,
    ...overrides,
  } satisfies ScanSighting;
}

const SEEN_AT = '2026-10-14T09:00:00.000Z';
const deps = (send: CredentialSightingsSend) => ({
  send,
  managedSettings: null,
  home: tempDir('aka-home-'),
  now: () => new Date(SEEN_AT),
});

function sharingMachine(): void {
  attach('machine');
  consent();
  holdKey();
}

describe('sightingLocationClass', () => {
  const home = '/home/someone';

  it('classes a file in the project, and one under a dot-directory of it', () => {
    const root = `${home}/code/widgets`;
    expect(sightingLocationClass(`${root}/src/config.ts`, root, home)).toBe('project-file');
    expect(sightingLocationClass(`${root}/.env`, root, home)).toBe('project-file');
    expect(sightingLocationClass(`${root}/.github/workflows/ci.yml`, root, home)).toBe(
      'project-dot-directory',
    );
    expect(sightingLocationClass(`${root}/deploy/.secrets/key`, root, home)).toBe(
      'project-dot-directory',
    );
  });

  it('classes a home dotfile when the project is the home directory or lies above it', () => {
    expect(sightingLocationClass(`${home}/.aws/credentials`, home, home)).toBe('home-dotfile');
    expect(sightingLocationClass(`${home}/.npmrc`, home, home)).toBe('home-dotfile');
    expect(sightingLocationClass(`${home}/.npmrc`, '/home', home)).toBe('home-dotfile');
    expect(sightingLocationClass(`${home}/notes/todo.txt`, home, home)).toBe('project-file');
  });

  it('classes a project inside a home dot-directory by the project, not the home', () => {
    const root = `${home}/.config/tool`;
    expect(sightingLocationClass(`${root}/settings.json`, root, home)).toBe('project-file');
  });

  it('has no class for a file outside the project and outside home dotfiles', () => {
    expect(sightingLocationClass('/srv/other/file', `${home}/code/widgets`, home)).toBeUndefined();
    expect(sightingLocationClass(`${home}/code/widgets`, `${home}/code/widgets`, home)).toBe(
      undefined,
    );
  });
});

describe('planSightingShare', () => {
  it('hands out the current key when the machine is attached, sharing and holds one', () => {
    sharingMachine();
    const plan = planSightingShare(store.home, { managedSettings: null });
    expect(plan.ok).toBe(true);
    if (plan.ok) {
      expect(plan.keys.current.keyVersion).toBe(4);
      expect(Buffer.from(plan.keys.current.key).equals(KEY_BYTES)).toBe(true);
      expect(plan.keys.previous).toEqual([]);
    }
  });

  it('hands out the previous versions still inside their overlap window', () => {
    attach('machine');
    consent();
    const later = new Date(Date.now() + 86_400_000).toISOString();
    const earlier = new Date(Date.now() - 1_000).toISOString();
    createSightingKeyStore('file', keysDir(store.home)).replace({
      ...STORED_KEY,
      fetchedAtMs: Date.now(),
      previous: [
        { keyVersion: 3, key: Buffer.alloc(32, 3).toString('base64url'), acceptedUntil: later },
        { keyVersion: 2, key: Buffer.alloc(32, 2).toString('base64url'), acceptedUntil: earlier },
      ],
    });
    const plan = planSightingShare(store.home, { managedSettings: null });
    expect(plan.ok && plan.keys.previous.map((k) => k.keyVersion)).toEqual([3]);
  });

  it('refuses a standalone machine, naming the sharing state', () => {
    holdKey();
    consent();
    expect(planSightingShare(store.home, { managedSettings: null })).toMatchObject({
      ok: false,
      outcome: { status: 'not-shared', reason: 'sharing-off', sharing: { mode: 'standalone' } },
    });
  });

  it('refuses an attached machine whose user has not opted in', () => {
    attach('machine');
    holdKey();
    expect(planSightingShare(store.home, { managedSettings: null })).toMatchObject({
      ok: false,
      outcome: { reason: 'sharing-off', sharing: { reason: 'not-opted-in' } },
    });
  });

  it('refuses when the managed settings pin sharing off', () => {
    sharingMachine();
    expect(
      planSightingShare(store.home, {
        managedSettings: {
          specVersion: 1,
          values: { sightingShareConsent: false },
          lockedFields: [],
        },
      }),
    ).toMatchObject({ ok: false, outcome: { reason: 'sharing-off' } });
  });

  it('refuses without a sighting key', () => {
    attach('machine');
    consent();
    expect(planSightingShare(store.home, { managedSettings: null })).toEqual({
      ok: false,
      outcome: { status: 'not-shared', reason: 'no-key' },
    });
  });

  it('refuses a run that opted out, and reports sharing off first when it is', () => {
    sharingMachine();
    expect(planSightingShare(store.home, { managedSettings: null, enabled: false })).toEqual({
      ok: false,
      outcome: { status: 'not-shared', reason: 'opt-out' },
    });
    expect(
      planSightingShare(store.home, {
        managedSettings: {
          specVersion: 1,
          values: { sightingShareConsent: false },
          lockedFields: [],
        },
        enabled: false,
      }),
    ).toMatchObject({ ok: false, outcome: { reason: 'sharing-off' } });
  });

  it('sends nothing for a run that opted out', async () => {
    sharingMachine();
    const root = tempDir('aka-project-');
    const rec = recorder();

    const outcome = await forwardCredentialSightings(
      store.home,
      { project: project(root), sightings: [sightingIn(join(root, 'a.ts'), VALUE_A)] },
      { ...deps(rec.send), enabled: false },
    );

    expect(outcome).toEqual({ status: 'not-shared', reason: 'opt-out' });
    expect(rec.requests).toEqual([]);
  });
});

describe('forwardCredentialSightings', () => {
  it("carries each sighting's previous-version tokens as its aliases", async () => {
    sharingMachine();
    const root = tempDir('aka-project-');
    const file = join(root, 'src', 'config.ts');
    const previousKey = { keyVersion: 3, key: new Uint8Array(Buffer.alloc(32, 5)) };
    const aliases = [sightingToken(previousKey, VALUE_A)];
    const rec = recorder();

    await forwardCredentialSightings(
      store.home,
      {
        project: project(root),
        sightings: [sightingIn(file, VALUE_A, { aliases }), sightingIn(file, VALUE_B)],
      },
      deps(rec.send),
    );

    const body = rec.requests[0];
    expect(RequestSchema.parse(body)).toEqual(body);
    expect(body?.sightings[0]?.aliases).toEqual(aliases);
    expect(body?.sightings[1]).not.toHaveProperty('aliases');
    const wire = JSON.stringify(body);
    expect(wire).not.toContain(VALUE_A);
    expect(wire).not.toContain(VALUE_B);
  });

  it('sends tokens with project, class, variable name and git-tracked, and nothing else', async () => {
    sharingMachine();
    const root = tempDir('aka-project-');
    writeGitRepo(root, ['src/config.ts']);
    const rec = recorder();
    const file = join(root, 'src', 'config.ts');
    const dotFile = join(root, '.github', 'deploy.yml');

    const outcome = await forwardCredentialSightings(
      store.home,
      {
        project: project(root),
        sightings: [
          sightingIn(file, VALUE_A),
          sightingIn(dotFile, VALUE_B, { variableName: undefined }),
        ],
      },
      deps(rec.send),
    );

    expect(outcome).toEqual({ status: 'sent', shared: 2, keptLocal: 0, unsent: 0 });
    expect(rec.connections).toEqual([{ endpoint: ENDPOINT, apiKey: CREDENTIAL_VALUE }]);
    expect(rec.requests).toHaveLength(1);
    const body = rec.requests[0];
    expect(RequestSchema.parse(body)).toEqual(body);
    const wireProject = { projectKey: hashProjectKey(`git:${REPO_URL}`), name: 'acme/widgets' };
    expect(body?.sightings).toEqual([
      {
        token: sightingToken(independentKey, VALUE_A),
        ruleId: 'aws-access-key',
        category: 'secret',
        variableName: 'AWS_ACCESS_KEY_ID',
        locationClass: 'project-file',
        project: wireProject,
        gitTracked: true,
        seenAt: SEEN_AT,
      },
      {
        token: sightingToken(independentKey, VALUE_B),
        ruleId: 'aws-access-key',
        category: 'secret',
        locationClass: 'project-dot-directory',
        project: wireProject,
        gitTracked: false,
        seenAt: SEEN_AT,
      },
    ]);
    expect(body?.scanId).toMatch(/^[0-9a-f-]{36}$/);

    const wire = JSON.stringify(rec.requests);
    expectNoEchoOf(wire, VALUE_A);
    expectNoEchoOf(wire, VALUE_B);
    for (const forbidden of [root, 'config.ts', 'deploy.yml', REPO_URL]) {
      expect(wire).not.toContain(forbidden);
    }
  });

  it('counts a value once per project and location class', async () => {
    sharingMachine();
    const root = tempDir('aka-project-');
    writeGitRepo(root, ['b.ts', '.vscode/c.json']);
    const rec = recorder();

    const outcome = await forwardCredentialSightings(
      store.home,
      {
        project: project(root),
        sightings: [
          sightingIn(join(root, 'a.ts'), VALUE_A, { variableName: undefined }),
          sightingIn(join(root, 'b.ts'), VALUE_A),
          sightingIn(join(root, '.vscode', 'c.json'), VALUE_A),
        ],
      },
      deps(rec.send),
    );

    expect(outcome).toMatchObject({ shared: 2 });
    expect(
      rec.requests[0]?.sightings.map((s) => [s.locationClass, s.gitTracked, s.variableName]),
    ).toEqual([
      ['project-file', true, 'AWS_ACCESS_KEY_ID'],
      ['project-dot-directory', true, 'AWS_ACCESS_KEY_ID'],
    ]);
  });

  it('marks git-tracked only a file in its repository index', async () => {
    sharingMachine();
    const root = tempDir('aka-project-');
    writeGitRepo(root, ['tracked.ts', 'ignored.env']);
    const outside = tempDir('aka-outside-');
    const rec = recorder();
    const values = ['tracked', 'never-added', 'ignored', 'outside'].map((v) => `${VALUE_B}${v}`);

    await forwardCredentialSightings(
      store.home,
      {
        project: project(root),
        sightings: [
          sightingIn(join(root, 'tracked.ts'), values[0] ?? ''),
          sightingIn(join(root, 'new.env'), values[1] ?? ''),
          sightingIn(join(root, '.env'), values[2] ?? ''),
          sightingIn(join(outside, 'x.ts'), values[3] ?? ''),
        ],
      },
      { ...deps(rec.send), home: outside },
    );

    const byToken = new Map(
      rec.requests.flatMap((r) => r.sightings).map((s) => [s.token, s.gitTracked]),
    );
    expect(values.map((v) => byToken.get(sightingToken(independentKey, v)))).toEqual([
      true,
      false,
      false,
      undefined,
    ]);
  });

  it('marks nothing git-tracked when the repository index cannot be read', async () => {
    sharingMachine();
    const root = tempDir('aka-project-');
    mkdirSync(join(root, '.git'));
    writeFileSync(join(root, '.git', 'index'), 'not an index');
    const rec = recorder();

    await forwardCredentialSightings(
      store.home,
      { project: project(root), sightings: [sightingIn(join(root, 'a.ts'), VALUE_A)] },
      deps(rec.send),
    );

    expect(rec.requests[0]?.sightings[0]?.gitTracked).toBe(false);
  });

  it('marks nothing git-tracked in a project that is not a git working tree', async () => {
    sharingMachine();
    const root = tempDir('aka-project-');
    const rec = recorder();

    await forwardCredentialSightings(
      store.home,
      {
        project: project(root, { projectKey: `path:${root}`, name: 'widgets' }),
        sightings: [sightingIn(join(root, 'a.ts'), VALUE_A)],
      },
      deps(rec.send),
    );

    expect(rec.requests[0]?.sightings[0]).toMatchObject({
      gitTracked: false,
      project: { projectKey: hashProjectKey(`path:${root}`), name: 'widgets' },
    });
    expect(JSON.stringify(rec.requests)).not.toContain(root);
  });

  it('classes a home dotfile and keeps a file it cannot class', async () => {
    sharingMachine();
    const home = tempDir('aka-home-');
    mkdirSync(join(home, '.aws'));
    const rec = recorder();

    const outcome = await forwardCredentialSightings(
      store.home,
      {
        project: project(home, { projectKey: `path:${home}`, name: 'someone' }),
        sightings: [
          sightingIn(join(home, '.aws', 'credentials'), VALUE_A),
          sightingIn(join(tempDir('aka-elsewhere-'), 'elsewhere.txt'), VALUE_B),
        ],
      },
      { ...deps(rec.send), home },
    );

    expect(outcome).toMatchObject({ shared: 1, keptLocal: 1 });
    expect(rec.requests[0]?.sightings.map((s) => s.locationClass)).toEqual(['home-dotfile']);
  });

  it('splits a large set into batches of the contract maximum', async () => {
    sharingMachine();
    const root = tempDir('aka-project-');
    const rec = recorder();
    const many = Array.from({ length: 501 }, (_, i) =>
      sightingIn(join(root, 'a.ts'), `${VALUE_A}${String(i)}`),
    );

    const outcome = await forwardCredentialSightings(
      store.home,
      { project: project(root), sightings: many },
      deps(rec.send),
    );

    expect(outcome).toMatchObject({ shared: 501, unsent: 0 });
    expect(rec.requests.map((r) => r.sightings.length)).toEqual([500, 1]);
    expect(new Set(rec.requests.map((r) => r.scanId)).size).toBe(1);
  });

  it('reports a failed batch and stops, without throwing', async () => {
    sharingMachine();
    const root = tempDir('aka-project-');
    const rec = recorder((n) => (n === 2 ? 'unreachable' : undefined));
    const many = Array.from({ length: 1001 }, (_, i) =>
      sightingIn(join(root, 'a.ts'), `${VALUE_A}${String(i)}`),
    );

    const outcome = await forwardCredentialSightings(
      store.home,
      { project: project(root), sightings: many },
      deps(rec.send),
    );

    expect(outcome).toEqual({
      status: 'sent',
      shared: 500,
      keptLocal: 0,
      unsent: 501,
      failure: 'unreachable',
    });
    expect(rec.requests).toHaveLength(2);
  });

  it('reads a sender that throws as unreachable', async () => {
    sharingMachine();
    const root = tempDir('aka-project-');

    const outcome = await forwardCredentialSightings(
      store.home,
      { project: project(root), sightings: [sightingIn(join(root, 'a.ts'), VALUE_A)] },
      deps(() => Promise.reject(new Error('boom'))),
    );

    expect(outcome).toEqual({
      status: 'sent',
      shared: 0,
      keptLocal: 0,
      unsent: 1,
      failure: 'unreachable',
    });
  });

  it('sends nothing when sharing was turned off after the scan started', async () => {
    attach('machine');
    holdKey();
    const root = tempDir('aka-project-');
    const rec = recorder();

    const outcome = await forwardCredentialSightings(
      store.home,
      { project: project(root), sightings: [sightingIn(join(root, 'a.ts'), VALUE_A)] },
      deps(rec.send),
    );

    expect(outcome).toMatchObject({ status: 'not-shared', reason: 'sharing-off' });
    expect(rec.requests).toEqual([]);
  });

  it('sends nothing from a standalone machine', async () => {
    consent();
    holdKey();
    const root = tempDir('aka-project-');
    const rec = recorder();

    const outcome = await forwardCredentialSightings(
      store.home,
      { project: project(root), sightings: [sightingIn(join(root, 'a.ts'), VALUE_A)] },
      deps(rec.send),
    );

    expect(outcome).toMatchObject({ status: 'not-shared', reason: 'sharing-off' });
    expect(rec.requests).toEqual([]);
  });

  it('keeps every sighting of a project a scoped attachment does not enroll', async () => {
    attach('scoped', ['github.com/acme/other']);
    consent();
    holdKey();
    const root = tempDir('aka-project-');
    const rec = recorder();

    const outcome = await forwardCredentialSightings(
      store.home,
      {
        project: project(root),
        sightings: [
          sightingIn(join(root, 'a.ts'), VALUE_A),
          sightingIn(join(root, 'b.ts'), VALUE_B),
        ],
      },
      deps(rec.send),
    );

    expect(outcome).toEqual({ status: 'sent', shared: 0, keptLocal: 2, unsent: 0 });
    expect(rec.requests).toEqual([]);
  });

  it('sends an enrolled project and keeps a sighting from a repository nested in it that is not', async () => {
    attach('scoped', [REPO_KEY]);
    consent();
    holdKey();
    const root = tempDir('aka-project-');
    const rec = recorder();

    const outcome = await forwardCredentialSightings(
      store.home,
      {
        project: project(root),
        sightings: [
          sightingIn(join(root, 'a.ts'), VALUE_A),
          sightingIn(join(root, 'vendor', 'x', 'b.ts'), VALUE_B, {
            scopeKey: 'github.com/someone/else',
          }),
          sightingIn(join(root, 'local', 'c.ts'), `${VALUE_B}c`, { scopeKey: undefined }),
        ],
      },
      deps(rec.send),
    );

    expect(outcome).toEqual({ status: 'sent', shared: 1, keptLocal: 2, unsent: 0 });
    expect(rec.requests[0]?.sightings.map((s) => s.token)).toEqual([
      sightingToken(independentKey, VALUE_A),
    ]);
  });

  it('counts a value kept local once however many files hold it', async () => {
    attach('scoped', ['github.com/acme/other']);
    consent();
    holdKey();
    const root = tempDir('aka-project-');
    const rec = recorder();

    const outcome = await forwardCredentialSightings(
      store.home,
      {
        project: project(root),
        sightings: [
          sightingIn(join(root, 'a.ts'), VALUE_A),
          sightingIn(join(root, 'b.ts'), VALUE_A),
          sightingIn(join(root, 'c.ts'), VALUE_A),
        ],
      },
      deps(rec.send),
    );

    expect(outcome).toEqual({ status: 'sent', shared: 0, keptLocal: 1, unsent: 0 });
  });

  it('keeps a path-keyed project on a scoped attachment', async () => {
    attach('scoped', [REPO_KEY]);
    consent();
    holdKey();
    const root = tempDir('aka-project-');
    const rec = recorder();

    const outcome = await forwardCredentialSightings(
      store.home,
      {
        project: project(root, { projectKey: `path:${root}` }),
        sightings: [sightingIn(join(root, 'a.ts'), VALUE_A)],
      },
      deps(rec.send),
    );

    expect(outcome).toMatchObject({ shared: 0, keptLocal: 1 });
    expect(rec.requests).toEqual([]);
  });

  it('answers no sightings as a send of none, without calling the sender', async () => {
    sharingMachine();
    const rec = recorder();

    const outcome = await forwardCredentialSightings(
      store.home,
      { project: project(tempDir('aka-project-')), sightings: [] },
      deps(rec.send),
    );

    expect(outcome).toEqual({ status: 'sent', shared: 0, keptLocal: 0, unsent: 0 });
    expect(rec.requests).toEqual([]);
  });
});
