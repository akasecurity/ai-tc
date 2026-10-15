import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import {
  ATTACHED_IDENTITY_FILENAME,
  attachedUserDigestOf,
  credentialDigestOf,
  dataDir,
  readAttachedIdentity,
  readControlPlaneCredentialFile,
  recordValidatedWorkAccount,
  SESSION_ACCOUNTS_DIRNAME,
  SETTINGS_FILENAME,
  settingsDir,
} from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { attachToControlPlane, detachFromControlPlane } from '../../app/(app)/settings/actions.ts';
import { type LoopbackServer, startLoopbackServer } from '../helpers/loopback.ts';
import { tempHomes } from '../helpers/temp-home.ts';

// What the dashboard's attach records of who the key belongs to: a digest-only
// record beside the credential for a scoped attach, none for a machine-wide one,
// and each session's account state cleared either way. Detach removes both. An
// address reads as personal data to a scanner, so each one here is built from
// parts.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

// Homes are removed when this FILE finishes, not after each test. See the helper.
const newHome = tempHomes('aka-web-attach-identity-');

/** High-entropy keys made at run time, so no key-shaped literal sits in the tree. */
const KEY = randomBytes(24).toString('base64url');
const ROTATED_KEY = randomBytes(24).toString('base64url');
const AT_SIGN = String.fromCharCode(64);
const ORGANIZATION = 'Example Org';
const WORKER = `Worker${AT_SIGN}Example.com`;
const COLLEAGUE = `colleague${AT_SIGN}example.com`;
const WORK_ORG = `claude:${randomUUID()}`;
const ENROLLED_AT = '2026-10-14T00:00:00.000Z';

let home: string;
let deployment: LoopbackServer;
let other: LoopbackServer;

const akaHome = (): string => join(home, '.aka');
const akaData = (): string => dataDir(akaHome());
const identityFile = (): string => join(akaData(), ATTACHED_IDENTITY_FILENAME);
const sessionAccounts = (): string => join(akaData(), SESSION_ACCOUNTS_DIRNAME);
const settingsFile = (): string => join(settingsDir(akaHome()), SETTINGS_FILENAME);

/** Answer every whoami as `userEmail` of `tenantName`. */
function answerAs(server: LoopbackServer, userEmail: string, tenantName = ORGANIZATION): void {
  server.reply((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        tenantName,
        userEmail,
        role: 'member',
        keyKind: 'plugin',
        serverTime: '2026-10-14T00:00:00.000Z',
      }),
    );
  });
}

async function attach(
  mode: 'machine' | 'scoped' | undefined,
  accessKey = KEY,
  endpoint = deployment.origin,
): Promise<void> {
  expect(
    await attachToControlPlane({ endpoint, accessKey, ...(mode === undefined ? {} : { mode }) }),
  ).toEqual({ ok: true });
}

function plantSessionAccountState(): void {
  mkdirSync(sessionAccounts(), { recursive: true });
  writeFileSync(join(sessionAccounts(), 's-1.log'), '{}\n');
}

/** Learn WORK_ORG under the credential on disk, as a hook that validated it would. */
function learnWorkOrg(): void {
  const read = readControlPlaneCredentialFile(settingsDir(akaHome()));
  if (!read.usable) throw new Error(`expected a usable credential, got ${read.reason}`);
  expect(
    recordValidatedWorkAccount(akaData(), {
      endpoint: deployment.origin,
      credential: read.credential,
      key: WORK_ORG,
    }),
  ).toBe('written');
}

/** The user's own settings file, raw. */
function storedSettings(): Record<string, unknown> {
  return JSON.parse(readFileSync(settingsFile(), 'utf8')) as Record<string, unknown>;
}

beforeEach(async () => {
  home = newHome();
  osHome.dir = home;
  deployment = await startLoopbackServer();
  other = await startLoopbackServer();
  answerAs(deployment, WORKER);
  answerAs(other, WORKER);
});

afterEach(async () => {
  await Promise.all([deployment.close(), other.close()]);
});

describe('the dashboard attach records who the key belongs to', () => {
  it('a scoped attach records the attached account as digests, and clears session-accounts', async () => {
    plantSessionAccountState();

    await attach('scoped');

    expect(readAttachedIdentity(akaData())).toMatchObject({
      endpoint: deployment.origin,
      credentialDigest: credentialDigestOf(KEY),
      attachedUserDigest: attachedUserDigestOf(WORKER),
      source: 'attach',
      workAccounts: [],
    });
    const bytes = readFileSync(identityFile(), 'utf8');
    for (const text of [WORKER, WORKER.toLowerCase(), ORGANIZATION, KEY]) {
      expect(bytes).not.toContain(text);
    }
    expect(existsSync(sessionAccounts())).toBe(false);
  });

  it('a key rotation keeps the learned orgs', async () => {
    await attach('scoped');
    learnWorkOrg();

    await attach(undefined, ROTATED_KEY);

    expect(readAttachedIdentity(akaData())).toMatchObject({
      credentialDigest: credentialDigestOf(ROTATED_KEY),
      workAccounts: [{ kind: 'account', identity: WORK_ORG }],
    });
  });

  it('a learned org never carries over to another attached user', async () => {
    await attach('scoped');
    learnWorkOrg();
    answerAs(deployment, COLLEAGUE);

    await attach(undefined, ROTATED_KEY);

    expect(readAttachedIdentity(akaData())).toMatchObject({
      attachedUserDigest: attachedUserDigestOf(COLLEAGUE),
      workAccounts: [],
    });
  });

  it('a re-attach to another organization starts with no learned org', async () => {
    await attach('scoped');
    learnWorkOrg();
    answerAs(deployment, WORKER, 'Other Org');

    await attach(undefined, ROTATED_KEY);

    expect(readAttachedIdentity(akaData())?.workAccounts).toEqual([]);
  });

  it('a re-attach to another deployment starts with no learned org', async () => {
    await attach('scoped');
    learnWorkOrg();

    await attach('scoped', ROTATED_KEY, other.origin);

    expect(readAttachedIdentity(akaData())).toMatchObject({
      endpoint: other.origin,
      workAccounts: [],
    });
  });

  it('a machine attach deletes the record and session-accounts', async () => {
    await attach('scoped');
    expect(existsSync(identityFile())).toBe(true);
    plantSessionAccountState();

    await attach('machine', ROTATED_KEY);

    expect(existsSync(identityFile())).toBe(false);
    expect(existsSync(sessionAccounts())).toBe(false);
  });

  it('a record that cannot be written leaves none, and the attach still succeeds', async () => {
    mkdirSync(identityFile(), { recursive: true });

    await attach('scoped');

    expect(readAttachedIdentity(akaData())).toBeUndefined();
    expect(readControlPlaneCredentialFile(settingsDir(akaHome()))).toMatchObject({
      usable: true,
      credential: { mode: 'scoped' },
    });
  });

  it.each([['off'], ['paused']])(
    "a key rotation keeps workSubscriptions %s and every entry's codingAgents",
    async (value) => {
      await attach('scoped');
      const optedOut = {
        endpoint: deployment.origin,
        tenantName: ORGANIZATION,
        userEmail: WORKER,
        workSubscriptions: value,
        entries: [
          { kind: 'account', identity: WORK_ORG, enrolledAt: ENROLLED_AT, codingAgents: true },
        ],
      };
      writeFileSync(
        settingsFile(),
        JSON.stringify({ ...storedSettings(), attachmentScope: optedOut }),
      );

      await attach(undefined, ROTATED_KEY);

      expect(storedSettings().attachmentScope).toEqual(optedOut);
    },
  );
});

describe('the dashboard attach keeps the opt-out of work-subscription recognition in a fresh list', () => {
  /** The list a fresh attach writes for WORKER on the deployment. */
  const fresh = (): Record<string, unknown> => ({
    endpoint: deployment.origin,
    tenantName: ORGANIZATION,
    userEmail: WORKER,
    entries: [],
  });

  /** A scoped attach, then `record` stored as the enrolled list, then the key rotated. */
  async function rotateOver(record: unknown): Promise<void> {
    await attach('scoped');
    writeFileSync(settingsFile(), JSON.stringify({ ...storedSettings(), attachmentScope: record }));
    await attach(undefined, ROTATED_KEY);
    expect(readControlPlaneCredentialFile(settingsDir(akaHome()))).toMatchObject({
      usable: true,
      credential: { mode: 'scoped' },
    });
  }

  const entry = (identity: string): Record<string, unknown> => ({
    kind: 'repo',
    identity,
    enrolledAt: ENROLLED_AT,
  });

  it.each<[string, (endpoint: string) => unknown]>([
    [
      'a record that names no account',
      (endpoint) => ({
        endpoint,
        workSubscriptions: 'off',
        entries: [entry('github.com/example-org/payments-api')],
      }),
    ],
    [
      'a record for another organization',
      (endpoint) => ({
        endpoint,
        tenantName: 'Other Org',
        userEmail: WORKER,
        workSubscriptions: 'off',
        entries: [],
      }),
    ],
    [
      'a record for another account',
      (endpoint) => ({
        endpoint,
        tenantName: ORGANIZATION,
        userEmail: COLLEAGUE,
        workSubscriptions: 'off',
        entries: [],
      }),
    ],
    [
      'a value this version reads as off',
      (endpoint) => ({ endpoint, workSubscriptions: 'paused', entries: [] }),
    ],
  ])('keeps the opt-out of %s', async (_how, record) => {
    await rotateOver(record(deployment.origin));

    expect(storedSettings().attachmentScope).toEqual({ ...fresh(), workSubscriptions: 'off' });
  });

  it('keeps the opt-out of a record left beside a machine-wide credential', async () => {
    await attach('machine');
    writeFileSync(
      settingsFile(),
      JSON.stringify({
        ...storedSettings(),
        attachmentScope: {
          endpoint: deployment.origin,
          tenantName: ORGANIZATION,
          userEmail: WORKER,
          workSubscriptions: 'off',
          entries: [],
        },
      }),
    );

    await attach('scoped', ROTATED_KEY);

    expect(storedSettings().attachmentScope).toEqual({ ...fresh(), workSubscriptions: 'off' });
  });

  it('keeps the opt-out and nothing else of the record it replaces', async () => {
    await rotateOver({
      endpoint: deployment.origin,
      tenantName: 'Other Org',
      userEmail: WORKER,
      workSubscriptions: 'off',
      builtBy: 'a newer build',
      entries: [
        entry('github.com/example-org/payments-api'),
        { kind: 'account', identity: WORK_ORG, enrolledAt: ENROLLED_AT, codingAgents: true },
        { kind: 'org', identity: 'example-org', enrolledAt: ENROLLED_AT },
      ],
    });

    expect(storedSettings().attachmentScope).toEqual({ ...fresh(), workSubscriptions: 'off' });
  });

  it.each<[string, (endpoint: string) => unknown]>([
    ['holds no opt-out', (endpoint) => ({ endpoint, entries: [] })],
    [
      'is for another deployment',
      () => ({
        endpoint: other.origin,
        tenantName: ORGANIZATION,
        userEmail: WORKER,
        workSubscriptions: 'off',
        entries: [],
      }),
    ],
    [
      'cannot be read: an organization name longer than this version accepts',
      (endpoint) => ({
        endpoint,
        tenantName: 'x'.repeat(201),
        userEmail: WORKER,
        workSubscriptions: 'off',
        entries: [],
      }),
    ],
    [
      'cannot be read: entries that are not a list',
      (endpoint) => ({ endpoint, workSubscriptions: 'off', entries: 'not a list' }),
    ],
    ['cannot be read: a value that is not a record', () => 'not a record'],
  ])('starts with recognition on when the record it replaces %s', async (_how, record) => {
    await rotateOver(record(deployment.origin));

    expect(storedSettings().attachmentScope).toEqual(fresh());
    expect(storedSettings().attachmentScope).not.toHaveProperty('workSubscriptions');
  });
});

describe('the dashboard detach', () => {
  it('detach removes session-accounts and the attached account', async () => {
    await attach('scoped');
    expect(existsSync(identityFile())).toBe(true);
    plantSessionAccountState();

    expect(await detachFromControlPlane()).toEqual({ ok: true });

    expect(existsSync(identityFile())).toBe(false);
    expect(existsSync(sessionAccounts())).toBe(false);
  });
});
