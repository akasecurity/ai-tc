import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  applyOnboarding,
  ATTACHED_IDENTITY_FILENAME,
  clearAttachmentDerivedState,
  credentialDigestOf,
  dataDir as dataDirOf,
  readAttachedIdentity,
  readBoundAttachedIdentity,
  recordValidatedWorkAccount,
  removeControlPlaneCredential,
  SETTINGS_FILENAME,
  settingsDir as settingsDirOf,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { createRemoteClient, RemoteClient } from '@akasecurity/remote';
import type { PluginWhoami } from '@akasecurity/schema';
import {
  ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  ATTACHED_CREDENTIAL_SPEC_VERSION,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { fixtureEmail } from '../../../plugin-sdk/test/helpers/transcript-builder.ts';
import { refreshAttachedIdentity } from '../../src/attached/identity-refresh.ts';
import { SYNC_REQUEST_TIMEOUT_MS } from '../../src/attached/policy-sync.ts';

// The sync child's one question: who this machine's key belongs to, asked for a
// scoped attachment whose identity record does not hold, and written only while
// the attachment is still the one it asked about. The deployment is a stub whose
// whoami answers as told and counts its calls; nothing reaches a network.

const ENDPOINT = 'https://plane.example.com';
const OTHER_ENDPOINT = 'https://other.example.com';
const KEY = `test-${randomUUID()}`;
const ROTATED_KEY = `test-${randomUUID()}`;
const MEMBER = fixtureEmail(`member-${randomUUID().slice(0, 8)}`);
const COLLEAGUE = fixtureEmail(`colleague-${randomUUID().slice(0, 8)}`);
const LEARNED = `claude:${randomUUID()}`;
const ACME = { tenantName: 'Acme', userEmail: MEMBER };

let base: string;
let calls: number;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-identity-refresh-'));
  calls = 0;
});

afterEach(() => {
  removeTree(base);
});

// `as const`: the credential writers take the version as the literal `2`.
const scoped = (apiKey: string, endpoint: string = ENDPOINT) =>
  ({
    specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
    mode: 'scoped',
    endpoint,
    apiKey,
  }) as const;

/** Mark this home attached to `endpoint`, with no credential on file. */
function attachSettings(endpoint: string, scope: unknown = { endpoint, entries: [] }): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint, attachedAt: '2026-10-01T09:00:00.000Z' },
      attachmentScope: scope,
    },
    base,
    null,
  );
}

/** Attach this home to ENDPOINT with `apiKey`; the scope record names no account unless given. */
function attach(
  mode: 'scoped' | 'machine',
  apiKey: string = KEY,
  scope: unknown = { endpoint: ENDPOINT, entries: [] },
): void {
  attachSettings(ENDPOINT, scope);
  writeControlPlaneCredential(
    settingsDirOf(base),
    mode === 'scoped'
      ? scoped(apiKey)
      : { specVersion: ATTACHED_CREDENTIAL_SPEC_VERSION, endpoint: ENDPOINT, apiKey },
  );
}

/** A deployment whose whoami answers `who`, after running `during`, and counts each call. */
function answering(
  who: Pick<PluginWhoami, 'tenantName' | 'userEmail'>,
  during?: () => void,
): typeof createRemoteClient {
  return () =>
    ({
      whoami: () => {
        calls += 1;
        during?.();
        return Promise.resolve({
          ...who,
          role: 'member',
          keyKind: 'plugin',
          serverTime: '2026-10-14T09:00:00.000Z',
        });
      },
    }) as unknown as RemoteClient;
}

const unreachable: typeof createRemoteClient = () =>
  ({
    whoami: () => {
      calls += 1;
      return Promise.reject(new Error('unreachable'));
    },
  }) as unknown as RemoteClient;

const paths = () => ({ base, settingsDir: settingsDirOf(base), dataDir: dataDirOf(base) });
const refresh = (createClient: typeof createRemoteClient) =>
  refreshAttachedIdentity(paths(), { createClient });
const settingsBytes = (): string =>
  readFileSync(join(settingsDirOf(base), SETTINGS_FILENAME), 'utf8');
const learnedKeys = (): string[] =>
  (readAttachedIdentity(dataDirOf(base))?.workAccounts ?? []).map((entry) => entry.identity);
const recordExists = (): boolean => existsSync(join(dataDirOf(base), ATTACHED_IDENTITY_FILENAME));

describe('refreshAttachedIdentity — when it asks', () => {
  it('asks once, and writes the record for a scoped attachment that holds none', async () => {
    attach('scoped');
    expect(await refresh(answering(ACME))).toBe('written');
    const record = readBoundAttachedIdentity(dataDirOf(base), ENDPOINT, scoped(KEY));
    expect(record?.source).toBe('whoami');
    expect(await refresh(answering(ACME))).toBe('current');
    expect(calls).toBe(1);
  });

  it.each<[string, () => void, string]>([
    ['an unattached machine', () => undefined, 'skipped'],
    [
      'an attached machine with no credential on file',
      () => {
        attachSettings(ENDPOINT);
      },
      'skipped',
    ],
    [
      'a machine-wide credential',
      () => {
        attach('machine');
      },
      'skipped',
    ],
    [
      'a record that already holds',
      () => {
        attach('scoped');
        writeAttachedIdentity(dataDirOf(base), { endpoint: ENDPOINT, apiKey: KEY, ...ACME });
      },
      'current',
    ],
  ])('makes no request for %s', async (_name, arrange, outcome) => {
    arrange();
    expect(await refresh(answering(ACME))).toBe(outcome);
    expect(calls).toBe(0);
  });

  it('asks the same whether or not work subscriptions are off', async () => {
    attach('scoped', KEY, { endpoint: ENDPOINT, entries: [], workSubscriptions: 'off' });
    expect(await refresh(answering(ACME))).toBe('written');
    expect(calls).toBe(1);
  });

  it('builds its client from the credential on file, bounded as the policy pull is', async () => {
    attach('scoped');
    const seen: unknown[] = [];
    const recording: typeof createRemoteClient = (options) => {
      seen.push(options);
      return answering(ACME)(options);
    };
    expect(await refresh(recording)).toBe('written');
    expect(seen).toEqual([{ endpoint: ENDPOINT, apiKey: KEY, timeoutMs: SYNC_REQUEST_TIMEOUT_MS }]);
  });

  it('gives up on a request that never answers, as the policy pull does', async () => {
    attach('scoped');
    const hung: typeof createRemoteClient = () =>
      ({
        whoami: () => {
          calls += 1;
          return new Promise<never>(() => undefined);
        },
      }) as unknown as RemoteClient;
    vi.useFakeTimers();
    try {
      const outcome = refresh(hung);
      await vi.advanceTimersByTimeAsync(SYNC_REQUEST_TIMEOUT_MS);
      expect(await outcome).toBe('failed');
      expect(recordExists()).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('writes nothing after a failed request, and asks again on the next run', async () => {
    attach('scoped');
    expect(await refresh(unreachable)).toBe('failed');
    expect(recordExists()).toBe(false);
    expect(await refresh(answering(ACME))).toBe('written');
    expect(calls).toBe(2);
  });

  it('lets two runs that overlap each ask, since nothing serialises them', async () => {
    attach('scoped');
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const held: typeof createRemoteClient = () =>
      ({
        whoami: async () => {
          calls += 1;
          await gate;
          return {
            ...ACME,
            role: 'member',
            keyKind: 'plugin',
            serverTime: '2026-10-14T09:00:00.000Z',
          };
        },
      }) as unknown as RemoteClient;
    const runs = [refresh(held), refresh(held)];
    await vi.waitFor(() => {
      expect(calls).toBe(2);
    });
    release();
    expect(await Promise.all(runs)).toEqual(['written', 'written']);
    expect(calls).toBe(2);
    expect(await refresh(answering(ACME))).toBe('current');
    expect(calls).toBe(2);
  });

  it('answers failed rather than throwing when the client cannot be built', async () => {
    attach('scoped');
    const broken: typeof createRemoteClient = () => {
      throw new Error('no client');
    };
    expect(await refresh(broken)).toBe('failed');
    expect(recordExists()).toBe(false);
  });
});

describe('refreshAttachedIdentity — what it writes', () => {
  // A record bound to KEY with one learned work account, then a key rotation by
  // a build that never touches the record: the record does not hold.
  function learnedThenRotated(): void {
    attach('scoped');
    writeAttachedIdentity(dataDirOf(base), { endpoint: ENDPOINT, apiKey: KEY, ...ACME });
    recordValidatedWorkAccount(dataDirOf(base), {
      endpoint: ENDPOINT,
      credential: scoped(KEY),
      key: LEARNED,
    });
    writeControlPlaneCredential(settingsDirOf(base), scoped(ROTATED_KEY));
  }

  it('an older build’s same-user rotation keeps the learned orgs', async () => {
    learnedThenRotated();
    expect(await refresh(answering(ACME))).toBe('written');
    expect(readAttachedIdentity(dataDirOf(base))?.credentialDigest).toBe(
      credentialDigestOf(ROTATED_KEY),
    );
    expect(learnedKeys()).toEqual([LEARNED]);
  });

  it.each<[string, Pick<PluginWhoami, 'tenantName' | 'userEmail'>]>([
    ['another user', { tenantName: 'Acme', userEmail: COLLEAGUE }],
    ['another organization', { tenantName: 'Other', userEmail: MEMBER }],
  ])('empties the learned orgs when the key now belongs to %s', async (_name, who) => {
    learnedThenRotated();
    expect(await refresh(answering(who))).toBe('written');
    expect(learnedKeys()).toEqual([]);
  });

  it('never writes the scope record, even one that names no account', async () => {
    attach('scoped');
    const before = settingsBytes();
    expect(await refresh(answering(ACME))).toBe('written');
    expect(settingsBytes()).toBe(before);
  });

  it('writes no record for an address that does not normalise, and asks again next run', async () => {
    attach('scoped');
    const unusable = { tenantName: 'Acme', userEmail: 'not an address' };
    expect(await refresh(answering(unusable))).toBe('failed');
    expect(recordExists()).toBe(false);
    expect(await refresh(answering(ACME))).toBe('written');
    expect(calls).toBe(2);
  });
});

describe('refreshAttachedIdentity — an attachment that changes while it asks', () => {
  it('writes nothing over a re-attach that lands while it asks', async () => {
    attach('scoped');
    const reattach = (): void => {
      writeControlPlaneCredential(settingsDirOf(base), scoped(ROTATED_KEY));
      writeAttachedIdentity(dataDirOf(base), {
        endpoint: ENDPOINT,
        apiKey: ROTATED_KEY,
        tenantName: 'Acme',
        userEmail: COLLEAGUE,
      });
    };
    expect(await refresh(answering(ACME, reattach))).toBe('raced');
    const record = readBoundAttachedIdentity(dataDirOf(base), ENDPOINT, scoped(ROTATED_KEY));
    expect(record?.source).toBe('attach');
  });

  it('writes nothing over a re-attach to another deployment under the same key', async () => {
    attach('scoped');
    const move = (): void => {
      attachSettings(OTHER_ENDPOINT);
      writeControlPlaneCredential(settingsDirOf(base), scoped(KEY, OTHER_ENDPOINT));
    };
    expect(await refresh(answering(ACME, move))).toBe('raced');
    expect(recordExists()).toBe(false);
  });

  it('writes nothing over a machine-wide re-attach under the same key', async () => {
    attach('scoped');
    const reattachMachineWide = (): void => {
      attach('machine');
    };
    expect(await refresh(answering(ACME, reattachMachineWide))).toBe('raced');
    expect(recordExists()).toBe(false);
  });

  it('leaves no record behind a detach that lands while it asks', async () => {
    attach('scoped');
    const detach = (): void => {
      removeControlPlaneCredential(settingsDirOf(base));
      clearAttachmentDerivedState(dataDirOf(base));
    };
    expect(await refresh(answering(ACME, detach))).toBe('raced');
    expect(recordExists()).toBe(false);
  });
});

describe('only the sync child asks who a key belongs to', () => {
  const PACKAGE = fileURLToPath(new URL('../../', import.meta.url));
  const SRC = join(PACKAGE, 'src');
  const sources = readdirSync(SRC, { recursive: true, encoding: 'utf8' }).filter((name) =>
    name.endsWith('.ts'),
  );
  const text = (name: string): string => readFileSync(join(SRC, name), 'utf8');

  it('no hook entry or status path constructs a client for whoami', () => {
    expect(sources.filter((name) => text(name).includes('.whoami('))).toEqual([
      join('attached', 'identity-refresh.ts'),
    ]);
    expect(sources.filter((name) => text(name).includes('refreshAttachedIdentity')).sort()).toEqual(
      [join('attached', 'identity-refresh.ts'), join('attached', 'sync-entry.ts')].sort(),
    );
    expect(text(join('attached', 'status.ts'))).not.toMatch(
      /@akasecurity\/remote|identity-refresh/,
    );
  });

  it('no plugin declares the remote transport, so no hook can construct a client', () => {
    const pluginsDir = join(PACKAGE, '..', '..', 'plugins');
    const manifests = readdirSync(pluginsDir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => join(pluginsDir, entry.name, 'package.json'))
      .filter((file) => existsSync(file));
    expect(manifests.length).toBeGreaterThan(0);
    const declaring = manifests.filter((file) => {
      const manifest = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
      return [
        manifest.dependencies,
        manifest.devDependencies,
        manifest.peerDependencies,
        manifest.optionalDependencies,
      ].some(
        (group) => typeof group === 'object' && group !== null && '@akasecurity/remote' in group,
      );
    });
    expect(declaring).toEqual([]);
  });

  it('the package exports only its root entry', () => {
    const manifest = JSON.parse(readFileSync(join(PACKAGE, 'package.json'), 'utf8')) as {
      exports: Record<string, string>;
    };
    expect(Object.keys(manifest.exports)).toEqual(['.']);
  });
});
