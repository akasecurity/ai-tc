import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import {
  controlPlaneCredentialPath,
  readWorkspaceSettings,
  SETTINGS_FILENAME,
  settingsDir,
} from '@akasecurity/persistence';
import type { ManagedSettings } from '@akasecurity/schema';
import { connectionRefusalMessage, MANAGED_SETTINGS_FILENAME } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../../../packages/persistence/src/managed-settings.ts';
import { attachToControlPlane, detachFromControlPlane } from '../../app/(app)/settings/actions.ts';
import { ATTACH_MODE_REQUIRED } from '../../app/lib/action-refusals.ts';
import { type LoopbackServer, startLoopbackServer } from '../helpers/loopback.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { tempHomes } from '../helpers/temp-home.ts';

// The dashboard's attach in a MODE. A personal device attaches scoped: a v2
// credential, and in the same settings write a scope record bound to the
// endpoint and to the organization and account the key verified as. An
// organization's device attaches machine-wide: today's v1 credential, byte for
// byte, and no scope record at all. A re-attach to the same deployment — how a
// key is rotated — keeps the mode and, for the same organization and account,
// every enrollment; anyone else starts empty. A governed connection is
// machine-wide.
//
// Both deployments are real servers on loopback, so a refusal "before the key
// is sent" is read off the wire as an empty `received`, not inferred.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

// Homes are removed when this FILE finishes, not after each test. See the helper.
const newHome = tempHomes('aka-web-attach-mode-');

/** High-entropy keys made at run time, so no key-shaped literal sits in the tree. */
const KEY = randomBytes(24).toString('base64url');
const ROTATED_KEY = randomBytes(24).toString('base64url');

const ORGANIZATION = 'Example Org';
const ACCOUNT = 'operator';

const ENTRY = {
  kind: 'repo',
  identity: 'github.com/acme/payments-api',
  enrolledAt: '2026-10-01T00:00:00.000Z',
};

let home: string;
let deployment: LoopbackServer;
let other: LoopbackServer;

const akaHome = (): string => join(home, '.aka');
const credentialFile = (): string => controlPlaneCredentialPath(settingsDir(akaHome()));
const settingsFile = (): string => join(settingsDir(akaHome()), SETTINGS_FILENAME);

/** Answer every whoami as `account` of `organization`. */
function answerAs(server: LoopbackServer, account: string, organization = ORGANIZATION): void {
  server.reply((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        tenantName: organization,
        userEmail: account,
        role: 'member',
        keyKind: 'plugin',
        serverTime: '2026-10-07T00:00:00.000Z',
      }),
    );
  });
}

function storedCredential(): Record<string, unknown> {
  return JSON.parse(readFileSync(credentialFile(), 'utf8')) as Record<string, unknown>;
}

/** The user's own settings file, raw: what the next writer merges over. */
function storedSettings(): Record<string, unknown> {
  return JSON.parse(readFileSync(settingsFile(), 'utf8')) as Record<string, unknown>;
}

/** Replace the stored scope record, as an enroll between two attaches would. */
function writeScope(scope: unknown): void {
  writeFileSync(settingsFile(), JSON.stringify({ ...storedSettings(), attachmentScope: scope }));
}

/** A bound record holding one enrollment. */
function enrolledFor(
  endpoint: string,
  account = ACCOUNT,
  organization = ORGANIZATION,
): Record<string, unknown> {
  return { endpoint, tenantName: organization, userEmail: account, entries: [ENTRY] };
}

/** The empty record a scoped attach starts with. */
function freshFor(
  endpoint: string,
  account = ACCOUNT,
  organization = ORGANIZATION,
): Record<string, unknown> {
  return { endpoint, tenantName: organization, userEmail: account, entries: [] };
}

/** Place an administrator's file inside this home and make it the one this process reads. */
function administer(overlay: ManagedSettings): void {
  const dir = join(home, 'administrator');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, MANAGED_SETTINGS_FILENAME);
  writeFileSync(file, JSON.stringify(overlay));
  UNSAFE_TEST_ONLY_setManagedSettingsPaths([file]);
}

const pinPlane = (endpoint: string): ManagedSettings => ({
  specVersion: 1,
  organization: ORGANIZATION,
  values: { controlPlane: { endpoint } },
  lockedFields: [],
});

const pinFleet = (endpoint: string): ManagedSettings => ({
  specVersion: 1,
  organization: ORGANIZATION,
  values: { runMode: 'attached', controlPlane: { endpoint } },
  lockedFields: [],
});

async function attachScoped(endpoint = deployment.origin): Promise<void> {
  expect(await attachToControlPlane({ endpoint, accessKey: KEY, mode: 'scoped' })).toEqual({
    ok: true,
  });
}

beforeEach(async () => {
  home = newHome();
  osHome.dir = home;
  deployment = await startLoopbackServer();
  other = await startLoopbackServer();
  answerAs(deployment, ACCOUNT);
  answerAs(other, ACCOUNT);
});

afterEach(async () => {
  // Back to the setup file's declaration: no administrator.
  UNSAFE_TEST_ONLY_setManagedSettingsPaths([]);
  await Promise.all([deployment.close(), other.close()]);
});

describe('a first attach', () => {
  it('writes a scoped credential and an empty scope bound to who the key verified as', async () => {
    await attachScoped();

    const credential = storedCredential();
    // Exactly these keys; their order on disk is the writer's, and no reader
    // depends on it for v2.
    expect(Object.keys(credential).sort()).toEqual([
      'apiKey',
      'endpoint',
      'mintedAt',
      'mode',
      'specVersion',
    ]);
    expect(credential).toMatchObject({
      specVersion: 2,
      mode: 'scoped',
      endpoint: deployment.origin,
    });
    expect(credential.apiKey).toBe(KEY);
    expect(storedSettings().attachmentScope).toEqual(freshFor(deployment.origin));
  });

  it('writes the machine-wide file byte for byte as before, and no scope record', async () => {
    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });

    const bytes = readFileSync(credentialFile(), 'utf8');
    const { mintedAt } = JSON.parse(bytes) as { mintedAt: string };
    // The literal this action wrote before modes existed, serialised the way
    // writeControlPlaneCredential always has: same keys, same order, nothing
    // added.
    expect(bytes).toBe(
      `${JSON.stringify({ specVersion: 1, endpoint: deployment.origin, apiKey: KEY, mintedAt }, null, 2)}\n`,
    );
    expect('attachmentScope' in storedSettings()).toBe(false);
  });

  it('attaches machine-wide when no mode is named and nothing is stored', async () => {
    expect(await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY })).toEqual({
      ok: true,
    });
    expect(storedCredential()).toMatchObject({ specVersion: 1, endpoint: deployment.origin });
    expect('mode' in storedCredential()).toBe(false);
    expect('attachmentScope' in storedSettings()).toBe(false);
  });
});

describe('a re-attach to the same deployment — a key rotation', () => {
  it('keeps a scoped machine scoped, with every enrollment, when no mode is named', async () => {
    await attachScoped();
    writeScope(enrolledFor(deployment.origin));

    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: ROTATED_KEY }),
    ).toEqual({ ok: true });

    expect(storedCredential()).toMatchObject({ specVersion: 2, mode: 'scoped' });
    expect(storedCredential().apiKey).toBe(ROTATED_KEY);
    expect(storedSettings().attachmentScope).toEqual(enrolledFor(deployment.origin));
  });

  it('keeps the enrollments when the scoped mode is named again', async () => {
    await attachScoped();
    writeScope(enrolledFor(deployment.origin));

    await attachScoped();

    expect(storedSettings().attachmentScope).toEqual(enrolledFor(deployment.origin));
  });

  it('keeps what a newer build added — an entry of an unknown kind, an envelope key', async () => {
    await attachScoped();
    const newer = {
      ...enrolledFor(deployment.origin),
      entries: [ENTRY, { kind: 'workspace', identity: 'acme:team', enrolledAt: ENTRY.enrolledAt }],
      retention: 'hold-all',
    };
    writeScope(newer);

    expect(await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY })).toEqual({
      ok: true,
    });

    // Kept as stored, never rebuilt from a parse that would drop both.
    expect(storedSettings().attachmentScope).toEqual(newer);
  });

  it('keeps a machine-wide machine machine-wide when no mode is named', async () => {
    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });
    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: ROTATED_KEY }),
    ).toEqual({ ok: true });

    expect(storedCredential()).toMatchObject({ specVersion: 1 });
    expect('attachmentScope' in storedSettings()).toBe(false);
  });

  it('widens on the machine choice: the machine-wide file, and the scope cleared', async () => {
    await attachScoped();
    writeScope(enrolledFor(deployment.origin));

    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });

    expect(Object.keys(storedCredential())).toEqual([
      'specVersion',
      'endpoint',
      'apiKey',
      'mintedAt',
    ]);
    expect(storedCredential().specVersion).toBe(1);
    expect('attachmentScope' in storedSettings()).toBe(false);

    // A later scoped attach starts empty rather than reviving the old list.
    await attachScoped();
    expect(storedSettings().attachmentScope).toEqual(freshFor(deployment.origin));
  });
});

describe('the binding', () => {
  it('starts empty when the key verifies as a different account', async () => {
    await attachScoped();
    writeScope(enrolledFor(deployment.origin));
    answerAs(deployment, 'someone-else');

    expect(await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY })).toEqual({
      ok: true,
    });

    // The mode is the machine's and is kept; the enrollments were someone else's.
    expect(storedCredential()).toMatchObject({ specVersion: 2, mode: 'scoped' });
    expect(storedSettings().attachmentScope).toEqual(freshFor(deployment.origin, 'someone-else'));
  });

  it('starts empty when the organization name differs', async () => {
    await attachScoped();
    writeScope(enrolledFor(deployment.origin));
    answerAs(deployment, ACCOUNT, 'Renamed Org');

    await attachScoped();

    expect(storedSettings().attachmentScope).toEqual(
      freshFor(deployment.origin, ACCOUNT, 'Renamed Org'),
    );
  });

  it('replaces a record that carries no binding, which nothing can check', async () => {
    await attachScoped();
    // The shape an older build's writer, or an enroll after one, leaves behind.
    writeScope({ endpoint: deployment.origin, entries: [ENTRY] });

    await attachScoped();

    expect(storedSettings().attachmentScope).toEqual(freshFor(deployment.origin));
  });

  it('binds a scoped attach to the new deployment, never the old one', async () => {
    await attachScoped();
    writeScope(enrolledFor(deployment.origin));

    await attachScoped(other.origin);

    expect(storedSettings().attachmentScope).toEqual(freshFor(other.origin));
  });

  it('starts empty over a bound record an older writer left beside a machine-wide key', async () => {
    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });
    // What an older build leaves after re-attaching a personal device machine-wide:
    // the bound record it did not know to clear.
    writeScope(enrolledFor(deployment.origin));

    await attachScoped();

    expect(storedSettings().attachmentScope).toEqual(freshFor(deployment.origin));
  });

  it('refuses to point a scoped machine at another deployment when no mode is named', async () => {
    // The stored credential is scoped and for a different endpoint. With no
    // terminal to ask on, a machine-wide attach there would widen the machine
    // with nobody deciding to, so the caller has to name the mode.
    await attachScoped();
    writeScope(enrolledFor(deployment.origin));
    const before = readFileSync(credentialFile(), 'utf8');

    expect(await attachToControlPlane({ endpoint: other.origin, accessKey: KEY })).toEqual({
      ok: false,
      error: ATTACH_MODE_REQUIRED,
    });

    expect(other.received).toEqual([]);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(before);
    expect(storedSettings().attachmentScope).toEqual(enrolledFor(deployment.origin));
  });

  it('attaches machine-wide to another deployment when no mode is named over a machine-wide key', async () => {
    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });

    expect(await attachToControlPlane({ endpoint: other.origin, accessKey: KEY })).toEqual({
      ok: true,
    });

    expect(storedCredential()).toMatchObject({ specVersion: 1, endpoint: other.origin });
    expect('attachmentScope' in storedSettings()).toBe(false);
  });
});

describe('a governed connection', () => {
  it.each<[string, (endpoint: string) => ManagedSettings]>([
    ['a pin on the connection alone', pinPlane],
    ['a pinned mode and connection', pinFleet],
  ])('refuses a scoped attach under %s, before the key is sent', async (_how, overlay) => {
    administer(overlay(deployment.origin));

    const res = await attachToControlPlane({
      endpoint: deployment.origin,
      accessKey: KEY,
      mode: 'scoped',
    });

    expect(res).toEqual({
      ok: false,
      error: connectionRefusalMessage({ reason: 'scoped-managed', organization: ORGANIZATION }),
    });
    expectNoEchoOf(res.error, KEY);
    expect(deployment.received).toEqual([]);
    expect(existsSync(credentialFile())).toBe(false);
    expect(existsSync(settingsFile())).toBe(false);
  });

  it('refuses a scoped attach under a lock, before the key is sent', async () => {
    // Attached unmanaged first: a lock with no value freezes the user's own
    // last choice, and a standalone machine under a lock is refused earlier.
    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });
    administer({
      specVersion: 1,
      organization: ORGANIZATION,
      values: {},
      lockedFields: ['runMode'],
    });
    const before = readFileSync(credentialFile(), 'utf8');

    const res = await attachToControlPlane({
      endpoint: deployment.origin,
      accessKey: ROTATED_KEY,
      mode: 'scoped',
    });

    expect(res).toEqual({
      ok: false,
      error: connectionRefusalMessage({ reason: 'scoped-managed', organization: ORGANIZATION }),
    });
    expect(deployment.received).toHaveLength(1);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(before);
  });

  it('refuses a scoped write when the machine became managed while the key was verified', async () => {
    deployment.reply((_req, res) => {
      // The overlay lands during the round trip, after the check before it.
      administer(pinPlane(deployment.origin));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          tenantName: ORGANIZATION,
          userEmail: ACCOUNT,
          role: 'member',
          keyKind: 'plugin',
          serverTime: '2026-10-07T00:00:00.000Z',
        }),
      );
    });

    const res = await attachToControlPlane({
      endpoint: deployment.origin,
      accessKey: KEY,
      mode: 'scoped',
    });

    expect(res).toEqual({
      ok: false,
      error: connectionRefusalMessage({ reason: 'scoped-managed', organization: ORGANIZATION }),
    });
    expect(deployment.received).toHaveLength(1);
    expect(existsSync(credentialFile())).toBe(false);
    expect(existsSync(settingsFile())).toBe(false);
  });

  it('attaches machine-wide under a pin when no mode is named', async () => {
    administer(pinPlane(deployment.origin));

    expect(await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY })).toEqual({
      ok: true,
    });

    expect(storedCredential()).toMatchObject({ specVersion: 1 });
    expect('attachmentScope' in storedSettings()).toBe(false);
  });

  it('takes a machine that became managed after a scoped attach machine-wide at its next attach', async () => {
    await attachScoped();
    writeScope(enrolledFor(deployment.origin));
    administer(pinPlane(deployment.origin));

    expect(await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY })).toEqual({
      ok: true,
    });

    expect(storedCredential()).toMatchObject({ specVersion: 1 });
    expect('attachmentScope' in storedSettings()).toBe(false);
    expect(readWorkspaceSettings(akaHome()).runMode).toBe('attached');
  });
});

describe('a credential file this build cannot read', () => {
  // It may be a scoped credential a newer build wrote. Writing a machine-wide
  // file over it because nobody named a mode would widen the machine silently.
  function plantUnreadable(): string {
    mkdirSync(settingsDir(akaHome()), { recursive: true, mode: 0o700 });
    const content = JSON.stringify({
      specVersion: 3,
      mode: 'scoped',
      endpoint: deployment.origin,
      apiKey: KEY,
    });
    writeFileSync(credentialFile(), content, { mode: 0o600 });
    return content;
  }

  it('refuses an attach that names no mode, before the key is sent', async () => {
    const content = plantUnreadable();

    const res = await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY });

    expect(res).toEqual({ ok: false, error: ATTACH_MODE_REQUIRED });
    expect(deployment.received).toEqual([]);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(content);
  });

  it('replaces it when the caller names the mode', async () => {
    plantUnreadable();

    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });

    expect(storedCredential()).toMatchObject({ specVersion: 1, endpoint: deployment.origin });
  });
});

describe('detachFromControlPlane', () => {
  it('clears the scope record with the attachment', async () => {
    await attachScoped();
    writeScope(enrolledFor(deployment.origin));

    expect(await detachFromControlPlane()).toEqual({ ok: true });

    expect('attachmentScope' in storedSettings()).toBe(false);
    expect(storedSettings().runMode).toBe('standalone');
    expect(existsSync(credentialFile())).toBe(false);
  });
});

describe('the input', () => {
  it('refuses a mode outside the vocabulary, naming the field and never the key', async () => {
    const res = await attachToControlPlane({
      endpoint: deployment.origin,
      accessKey: KEY,
      mode: 'everything',
    });

    expect(res.ok).toBe(false);
    expect(res.error).toContain("'mode'");
    expectNoEchoOf(res.error, KEY);
    expect(deployment.received).toEqual([]);
  });
});
