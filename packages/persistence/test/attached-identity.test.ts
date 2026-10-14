import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { AttachedCredentialAny, WorkspaceSettings } from '@akasecurity/schema';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ATTACHED_IDENTITY_FILENAME } from '../src/attached-derived.ts';
import type { WorkAccountWrite } from '../src/attached-identity.ts';
import {
  attachedUserDigestOf,
  bindingHashOf,
  codingScopeExtras,
  codingScopeExtrasAt,
  credentialDigestOf,
  forgetWorkAccounts,
  readAttachedIdentity,
  readBoundAttachedIdentity,
  recordValidatedWorkAccount,
  removeAttachedIdentity,
  scopeTagOf,
  WORK_ACCOUNT_LOCK_TIMEOUT_MS,
  writeAttachedIdentity,
} from '../src/attached-identity.ts';
import { writeControlPlaneCredential } from '../src/control-plane-credential.ts';
import type * as FileLock from '../src/file-lock.ts';
import { withFileLock } from '../src/file-lock.ts';
import { SESSION_ACCOUNTS_DIRNAME } from '../src/session-accounts.ts';
import { useTempStore } from './helpers/temp-store.ts';

// Every lock the record's writers take, with the timeout each asked for. The
// real lock still runs underneath.
const locks = vi.hoisted(() => ({
  calls: [] as { file: string; timeoutMs: number | undefined }[],
}));
vi.mock('../src/file-lock.ts', async (importActual) => {
  const actual = await importActual<typeof FileLock>();
  return {
    ...actual,
    withFileLock: <T>(file: string, fn: () => T, options?: FileLock.FileLockOptions): T => {
      locks.calls.push({ file, timeoutMs: options?.timeoutMs });
      return actual.withFileLock(file, fn, options);
    },
  };
});

// The record of who attached this machine, as digests beside the credential it
// belongs to. An address reads as personal data to a scanner, so each one here
// is built from parts.
const store = useTempStore('aka-attached-identity-');

const AT_SIGN = String.fromCharCode(64);
const EMAIL = `Worker${AT_SIGN}Example.test`;
const OTHER_EMAIL = `colleague${AT_SIGN}example.test`;
const ENDPOINT = 'https://plane.example.test';
const OTHER_ENDPOINT = 'https://other.example.test';
const TENANT = 'Example Org';
const KEY = 'key-1';
const ROTATED_KEY = 'key-2';
const WORK_ORG = 'claude:2ef4cd3c-c23c-473a-96be-1275cfc79103';
const MANUAL = 'claude:4020923d-217a-456c-92e8-82604103adda';
const WEB_ONLY = 'claude:50923026-c44f-4f2e-a6b0-b51ce5fc8351';
const NOW = new Date('2026-10-14T09:00:00.000Z');

type Cred = Readonly<AttachedCredentialAny>;

const scoped = (apiKey = KEY): AttachedCredentialAny => ({
  specVersion: 2,
  endpoint: ENDPOINT,
  apiKey,
  mintedAt: NOW.toISOString(),
  mode: 'scoped',
});
const machine = (apiKey = KEY): AttachedCredentialAny => ({
  specVersion: 1,
  endpoint: ENDPOINT,
  apiKey,
  mintedAt: NOW.toISOString(),
});
const sha256 = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');
const fileOf = (): string => join(store.dataDir, ATTACHED_IDENTITY_FILENAME);
const userDigest = (): string => attachedUserDigestOf(EMAIL) ?? '';
const tag = (): string => scopeTagOf(ENDPOINT, TENANT, userDigest());
const orgN = (n: number): string =>
  `claude:${String(n).padStart(8, '0')}-0000-4000-8000-000000000000`;

const attach = (
  over: Partial<{ endpoint: string; apiKey: string; tenantName: string; userEmail: string }> = {},
): boolean =>
  writeAttachedIdentity(
    store.dataDir,
    { endpoint: ENDPOINT, apiKey: KEY, tenantName: TENANT, userEmail: EMAIL, ...over },
    NOW,
  );
const learn = (key = WORK_ORG, held: Cred = scoped()): WorkAccountWrite =>
  recordValidatedWorkAccount(store.dataDir, { endpoint: ENDPOINT, credential: held, key }, NOW);
const learned = (key: string) => ({
  kind: 'account',
  identity: key,
  label: 'Claude work account',
  enrolledAt: NOW.toISOString(),
});
const plantSessionAccountState = (): string => {
  const dir = join(store.dataDir, SESSION_ACCOUNTS_DIRNAME);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 's-1.log'), '{}\n');
  return dir;
};

afterEach(() => {
  locks.calls.length = 0;
});

describe('the digests', () => {
  it('the credential digest is never the bare hash of the key', () => {
    expect(credentialDigestOf(KEY)).not.toBe(sha256(KEY));
    expect(credentialDigestOf(KEY)).toBe(sha256(`aka-credential-binding:v1\n${KEY}`));
  });

  it('digests the attached user by the normalized email, under its own prefix', () => {
    expect(attachedUserDigestOf(EMAIL)).toBe(
      sha256(`aka-attached-user:v1\n${EMAIL.toLowerCase()}`),
    );
    expect(attachedUserDigestOf(` ${EMAIL.toLowerCase()} `)).toBe(attachedUserDigestOf(EMAIL));
    expect(attachedUserDigestOf('member-17')).toBeUndefined();
  });

  it('gives the same tag for the same user, endpoint and organization, and another otherwise', () => {
    expect(tag()).toMatch(/^[0-9a-f]{16}$/);
    expect(tag()).toBe(
      sha256(`aka-agent-scope:v1\n${ENDPOINT}\n${TENANT}\n${userDigest()}`).slice(0, 16),
    );
    expect(scopeTagOf(ENDPOINT, TENANT, attachedUserDigestOf(OTHER_EMAIL) ?? '')).not.toBe(tag());
    expect(scopeTagOf(ENDPOINT, 'Other Org', userDigest())).not.toBe(tag());
    expect(scopeTagOf(OTHER_ENDPOINT, TENANT, userDigest())).not.toBe(tag());
  });

  it('binds session state to the endpoint, the credential and the user', () => {
    const digest = credentialDigestOf(KEY);
    expect(bindingHashOf(ENDPOINT, digest, userDigest())).toBe(
      sha256(`aka-session-binding:v1\n${ENDPOINT}\n${digest}\n${userDigest()}`).slice(0, 16),
    );
    expect(bindingHashOf(ENDPOINT, credentialDigestOf(ROTATED_KEY), userDigest())).not.toBe(
      bindingHashOf(ENDPOINT, digest, userDigest()),
    );
  });
});

describe('writeAttachedIdentity', () => {
  it('writes the record owner-only, bound to the endpoint and the credential', () => {
    expect(attach()).toBe(true);
    expect(readAttachedIdentity(store.dataDir)).toStrictEqual({
      specVersion: 1,
      endpoint: ENDPOINT,
      credentialDigest: credentialDigestOf(KEY),
      attachedUserDigest: userDigest(),
      scopeTag: tag(),
      source: 'attach',
      checkedAt: NOW.toISOString(),
      workAccounts: [],
    });
    if (process.platform !== 'win32') expect(statSync(fileOf()).mode & 0o777).toBe(0o600);
  });

  it('the record holds no email bytes', () => {
    attach();
    const bytes = readFileSync(fileOf(), 'utf8');
    for (const text of [EMAIL, EMAIL.toLowerCase(), EMAIL.toUpperCase(), 'orker', TENANT, KEY]) {
      expect(bytes).not.toContain(text);
    }
    expect(bytes).not.toContain(AT_SIGN);
  });

  it("clears every session's account state", () => {
    const dir = plantSessionAccountState();
    attach();
    expect(existsSync(dir)).toBe(false);
  });

  it('a key rotation keeps the learned orgs', () => {
    attach();
    expect(learn()).toBe('written');
    attach({ apiKey: ROTATED_KEY });
    expect(readAttachedIdentity(store.dataDir)).toMatchObject({
      credentialDigest: credentialDigestOf(ROTATED_KEY),
      workAccounts: [learned(WORK_ORG)],
    });
  });

  it.each([
    ['another attached user', { userEmail: OTHER_EMAIL }],
    ['another organization', { tenantName: 'Other Org' }],
    ['another endpoint', { endpoint: OTHER_ENDPOINT }],
  ])('a learned org never carries over to %s', (_label, over) => {
    attach();
    expect(learn()).toBe('written');
    attach({ apiKey: ROTATED_KEY, ...over });
    expect(readAttachedIdentity(store.dataDir)?.workAccounts).toEqual([]);
  });

  it('keeps, across a rotation, a work account a newer build learned that this build cannot read', () => {
    attach();
    const newer = {
      kind: 'account',
      identity: 'example:65f94956-0480-40e0-8f32-57f82813e476',
      enrolledAt: NOW.toISOString(),
    };
    const stored = JSON.parse(readFileSync(fileOf(), 'utf8')) as Record<string, unknown>;
    writeFileSync(fileOf(), JSON.stringify({ ...stored, workAccounts: [newer] }));
    attach({ apiKey: ROTATED_KEY });
    const after = JSON.parse(readFileSync(fileOf(), 'utf8')) as { workAccounts: unknown };
    expect(after.workAccounts).toEqual([newer]);
  });

  it('writes no record for an email that does not normalize, and removes the one stored', () => {
    attach();
    expect(attach({ userEmail: 'member-17' })).toBe(false);
    expect(existsSync(fileOf())).toBe(false);
  });

  it('reports a write that fails, and leaves no record', () => {
    mkdirSync(fileOf());
    expect(attach()).toBe(false);
    expect(readAttachedIdentity(store.dataDir)).toBeUndefined();
  });

  it('writes and clears nothing once the caller says, inside the lock, that the write is stale', () => {
    attach();
    const before = readFileSync(fileOf(), 'utf8');
    const dir = plantSessionAccountState();
    locks.calls.length = 0;
    let locksWhenAsked = -1;
    const written = writeAttachedIdentity(
      store.dataDir,
      {
        endpoint: ENDPOINT,
        apiKey: ROTATED_KEY,
        tenantName: TENANT,
        userEmail: EMAIL,
        source: 'whoami',
        stillCurrent: () => {
          locksWhenAsked = locks.calls.length;
          return false;
        },
      },
      NOW,
    );
    expect(written).toBe(false);
    expect(locksWhenAsked).toBe(1);
    expect(readFileSync(fileOf(), 'utf8')).toBe(before);
    expect(existsSync(dir)).toBe(true);
  });

  it('writes a refresh that is still current, with its source', () => {
    attach();
    const written = writeAttachedIdentity(
      store.dataDir,
      {
        endpoint: ENDPOINT,
        apiKey: ROTATED_KEY,
        tenantName: TENANT,
        userEmail: EMAIL,
        source: 'whoami',
        stillCurrent: () => true,
      },
      NOW,
    );
    expect(written).toBe(true);
    expect(readAttachedIdentity(store.dataDir)).toMatchObject({
      credentialDigest: credentialDigestOf(ROTATED_KEY),
      source: 'whoami',
    });
  });
});

describe('readBoundAttachedIdentity', () => {
  it('counts only for the endpoint and the credential it was written for, on a scoped attachment', () => {
    attach();
    expect(readBoundAttachedIdentity(store.dataDir, ENDPOINT, scoped())).toMatchObject({
      endpoint: ENDPOINT,
    });
    expect(readBoundAttachedIdentity(store.dataDir, ENDPOINT, scoped(ROTATED_KEY))).toBeUndefined();
    expect(readBoundAttachedIdentity(store.dataDir, OTHER_ENDPOINT, scoped())).toBeUndefined();
    expect(readBoundAttachedIdentity(store.dataDir, ENDPOINT, machine())).toBeUndefined();
    expect(readBoundAttachedIdentity(store.dataDir, ENDPOINT, undefined)).toBeUndefined();
    expect(readBoundAttachedIdentity(store.dataDir, undefined, scoped())).toBeUndefined();
  });
});

describe('removeAttachedIdentity', () => {
  it("deletes the record and every session's account state", () => {
    attach();
    const dir = plantSessionAccountState();
    expect(removeAttachedIdentity(store.dataDir)).toBe(true);
    expect(existsSync(fileOf())).toBe(false);
    expect(existsSync(dir)).toBe(false);
  });

  it('is not an error with nothing to remove', () => {
    expect(removeAttachedIdentity(store.dataDir)).toBe(true);
  });
});

describe('recordValidatedWorkAccount', () => {
  it('re-checks the binding inside the lock, and writes nothing for another credential', () => {
    attach();
    expect(learn(WORK_ORG, scoped(ROTATED_KEY))).toBe('refused');
    expect(learn(WORK_ORG, machine())).toBe('refused');
    expect(
      recordValidatedWorkAccount(
        store.dataDir,
        { endpoint: OTHER_ENDPOINT, credential: scoped(), key: WORK_ORG },
        NOW,
      ),
    ).toBe('refused');
    expect(readAttachedIdentity(store.dataDir)?.workAccounts).toEqual([]);
  });

  it('writes a key once, and never changes who the record says attached', () => {
    attach();
    const before = readAttachedIdentity(store.dataDir);
    expect(learn()).toBe('written');
    expect(
      recordValidatedWorkAccount(
        store.dataDir,
        { endpoint: ENDPOINT, credential: scoped(), key: WORK_ORG },
        new Date('2026-10-15T00:00:00.000Z'),
      ),
    ).toBe('present');
    const after = readAttachedIdentity(store.dataDir);
    expect(after?.workAccounts).toEqual([learned(WORK_ORG)]);
    expect({ ...after, workAccounts: [] }).toStrictEqual(before);
  });

  it('refuses a ninth key', () => {
    attach();
    for (let n = 1; n <= 8; n += 1) expect(learn(orgN(n))).toBe('written');
    expect(learn(orgN(9))).toBe('refused');
    expect(readAttachedIdentity(store.dataDir)?.workAccounts).toHaveLength(8);
  });

  it.each([
    ['a repository key', 'github.com/acme/payments-api'],
    ['an agent key', `agent:0123456789abcdef:${WORK_ORG}`],
    [
      'an account key this build has no provider for',
      'example:65f94956-0480-40e0-8f32-57f82813e476',
    ],
  ])('writes nothing for %s', (_label, key) => {
    attach();
    expect(learn(key)).toBe('refused');
    expect(readAttachedIdentity(store.dataDir)?.workAccounts).toEqual([]);
  });

  it('answers a timeout when the lock is held, writing nothing and throwing nothing', () => {
    attach();
    let result: WorkAccountWrite | undefined;
    withFileLock(fileOf(), () => {
      result = learn();
    });
    expect(result).toBe('timeout');
    expect(readAttachedIdentity(store.dataDir)?.workAccounts).toEqual([]);
  });

  it("waits at most 200 ms for the record's lock", () => {
    attach();
    locks.calls.length = 0;
    learn();
    expect(WORK_ACCOUNT_LOCK_TIMEOUT_MS).toBe(200);
    expect(locks.calls).toEqual([{ file: fileOf(), timeoutMs: WORK_ACCOUNT_LOCK_TIMEOUT_MS }]);
  });
});

describe('forgetWorkAccounts', () => {
  it('empties the learned orgs and keeps who attached', () => {
    attach();
    learn();
    const before = readAttachedIdentity(store.dataDir);
    expect(forgetWorkAccounts(store.dataDir, { endpoint: ENDPOINT, credential: scoped() })).toBe(
      true,
    );
    expect(readAttachedIdentity(store.dataDir)).toStrictEqual({ ...before, workAccounts: [] });
  });

  it('re-checks the binding, and changes nothing for another credential', () => {
    attach();
    learn();
    expect(
      forgetWorkAccounts(store.dataDir, { endpoint: ENDPOINT, credential: scoped(ROTATED_KEY) }),
    ).toBe(false);
    expect(readAttachedIdentity(store.dataDir)?.workAccounts).toHaveLength(1);
  });

  it('keeps every other key as found', () => {
    attach();
    learn();
    const stored = JSON.parse(readFileSync(fileOf(), 'utf8')) as Record<string, unknown>;
    writeFileSync(fileOf(), JSON.stringify({ ...stored, refreshedBy: 'a newer build' }));
    forgetWorkAccounts(store.dataDir, { endpoint: ENDPOINT, credential: scoped() });
    expect(JSON.parse(readFileSync(fileOf(), 'utf8'))).toStrictEqual({
      ...stored,
      refreshedBy: 'a newer build',
      workAccounts: [],
    });
  });
});

describe('codingScopeExtras', () => {
  const settingsWith = (
    attachmentScope: unknown,
    endpoint = ENDPOINT,
  ): Pick<WorkspaceSettings, 'controlPlane' | 'attachmentScope'> => ({
    controlPlane: { endpoint, attachedAt: NOW.toISOString() },
    attachmentScope,
  });
  const entry = (identity: string, over: Record<string, unknown> = {}) => ({
    kind: 'account',
    identity,
    enrolledAt: NOW.toISOString(),
    ...over,
  });
  const scopeRecord = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
    endpoint: ENDPOINT,
    entries: [
      entry(MANUAL, { codingAgents: true }),
      entry(WEB_ONLY),
      {
        kind: 'repo',
        identity: 'github.com/acme/payments-api',
        enrolledAt: NOW.toISOString(),
        codingAgents: true,
      },
    ],
    ...over,
  });
  const agent = (account: string): string => `agent:${tag()}:${account}`;
  const keysOf = (attachmentScope: unknown, held: Cred | undefined = scoped()): string[] =>
    codingScopeExtras(store.dataDir, settingsWith(attachmentScope), held).map((e) => e.identity);

  it('includes the learned orgs while recognition is on, so an absent field includes them', () => {
    attach();
    learn();
    expect(keysOf(scopeRecord())).toEqual([agent(WORK_ORG), agent(MANUAL)]);
    expect(keysOf(undefined)).toEqual([agent(WORK_ORG)]);
  });

  it('keeps only the entries enrolled by hand once recognition is off', () => {
    attach();
    learn();
    expect(keysOf(scopeRecord({ workSubscriptions: 'off' }))).toEqual([agent(MANUAL)]);
  });

  it.each([['paused'], [42], [null], [true]])('an unknown value reads as off: %s', (value) => {
    attach();
    learn();
    expect(keysOf(scopeRecord({ workSubscriptions: value }))).toEqual([agent(MANUAL)]);
  });

  it('covers an entry enrolled by hand only with codingAgents, never a web-only entry or a repository', () => {
    attach();
    const handEditedAgentKey = `agent:0123456789abcdef:${WORK_ORG}`;
    const entries = [
      ...(scopeRecord().entries as unknown[]),
      entry(handEditedAgentKey, { codingAgents: true }),
    ];
    expect(keysOf(scopeRecord({ entries }))).toEqual([agent(MANUAL)]);
  });

  it('is empty unless the record counts for this endpoint and credential', () => {
    attach();
    learn();
    expect(keysOf(scopeRecord(), scoped(ROTATED_KEY))).toEqual([]);
    expect(keysOf(scopeRecord(), machine())).toEqual([]);
    // Called directly: `undefined` handed to keysOf would take its default.
    expect(codingScopeExtras(store.dataDir, settingsWith(scopeRecord()), undefined)).toEqual([]);
    expect(
      codingScopeExtras(store.dataDir, settingsWith(scopeRecord(), OTHER_ENDPOINT), scoped()),
    ).toEqual([]);
    removeAttachedIdentity(store.dataDir);
    expect(keysOf(scopeRecord())).toEqual([]);
  });

  it('never hands back a bare account key, which would select web chat rows', () => {
    attach();
    learn();
    const extras = codingScopeExtras(store.dataDir, settingsWith(scopeRecord()), scoped());
    expect(extras).toHaveLength(2);
    for (const extra of extras) {
      expect(extra.kind).toBe('account');
      expect(extra.identity.startsWith('agent:')).toBe(true);
    }
  });

  it('lists an org both learned and enrolled by hand once', () => {
    attach();
    learn(MANUAL);
    expect(keysOf(scopeRecord())).toEqual([agent(MANUAL)]);
  });

  it('ignores the entries of a scope record for another deployment', () => {
    attach();
    expect(keysOf(scopeRecord({ endpoint: OTHER_ENDPOINT }))).toEqual([]);
  });

  it('reads the credential itself when handed only the settings directory', () => {
    attach();
    learn();
    const at = (): string[] =>
      codingScopeExtrasAt(store.settingsDir, store.dataDir, settingsWith(scopeRecord())).map(
        (e) => e.identity,
      );
    expect(at()).toEqual([]);
    writeControlPlaneCredential(store.settingsDir, machine());
    expect(at()).toEqual([]);
    writeControlPlaneCredential(store.settingsDir, scoped());
    expect(at()).toEqual([agent(WORK_ORG), agent(MANUAL)]);
    writeControlPlaneCredential(store.settingsDir, scoped(ROTATED_KEY));
    expect(at()).toEqual([]);
  });
});
