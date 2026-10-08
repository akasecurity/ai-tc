import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  applyOnboarding,
  controlPlaneCredentialPath,
  readWorkspaceSettings,
  SETTINGS_FILENAME,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { HistorySyncConsent, ManagedSettings } from '@akasecurity/schema';
import {
  connectionRefusalMessage,
  HISTORY_SYNC_PAYLOAD_VERSION,
  MANAGED_SETTINGS_FILENAME,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../../../packages/persistence/src/managed-settings.ts';
import { attachToControlPlane, detachFromControlPlane } from '../../app/(app)/settings/actions.ts';
import {
  ATTACH_CHANGED_WHILE_WAITING,
  ATTACH_CREDENTIAL_UNWRITABLE,
  ATTACH_MODE_REQUIRED,
} from '../../app/lib/action-refusals.ts';
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
/** The key another aka on the same machine attaches with. */
const OTHER_AKA_KEY = randomBytes(24).toString('base64url');

/** The scoped credential the terminal command writes, as captured by the frozen-reader suite. */
const CLI_SCOPED_CREDENTIAL = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
  'packages',
  'plugin-sdk',
  'test',
  'fixtures',
  'cli-scoped-credential-v2.json',
);

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

/**
 * Answer every whoami as `account` of `organization`. `during` runs as the reply
 * is made, which is the key being verified: the moment another process on this
 * machine can change what the attach decided from.
 */
function answerAs(
  server: LoopbackServer,
  account: string,
  organization = ORGANIZATION,
  during?: () => void,
): void {
  server.reply((_req, res) => {
    during?.();
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
    // Exactly these keys, in the order the terminal command writes them with
    // `mode` last, where the schema's own parse puts it: a rollback by either
    // surface then restores the same bytes.
    const bytes = readFileSync(credentialFile(), 'utf8');
    const { mintedAt } = credential as { mintedAt: string };
    expect(bytes).toBe(
      `${JSON.stringify(
        { specVersion: 2, endpoint: deployment.origin, apiKey: KEY, mintedAt, mode: 'scoped' },
        null,
        2,
      )}\n`,
    );
    expect(Object.keys(credential)).toEqual(
      Object.keys(JSON.parse(readFileSync(CLI_SCOPED_CREDENTIAL, 'utf8')) as object),
    );
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

describe('a settings directory the earlier credential cannot be read from', () => {
  // A regular FILE where ~/.aka/settings should be a directory: the read of the
  // credential on file raises rather than answering, and the write that would
  // follow fails on the same fault. Windows reports a path through a file
  // differently, so these cases are POSIX-only.
  it.for([undefined, 'machine', 'scoped'] as const)(
    'refuses before the key is sent, with the mode %s',
    async (mode, ctx) => {
      if (process.platform === 'win32') {
        ctx.skip('A file where the settings directory belongs reads as ENOTDIR on POSIX only');
        return;
      }
      mkdirSync(akaHome(), { recursive: true });
      writeFileSync(settingsDir(akaHome()), 'not a directory');

      const res = await attachToControlPlane({
        endpoint: deployment.origin,
        accessKey: KEY,
        ...(mode === undefined ? {} : { mode }),
      });

      expect(res).toEqual({ ok: false, error: ATTACH_CREDENTIAL_UNWRITABLE });
      expectNoEchoOf(res.error, KEY);
      expect(deployment.received).toEqual([]);
    },
  );
});

describe('another aka changes the machine while the key is verified', () => {
  // The mode was decided from the credential read before the key went out, and
  // the reply can take seconds. A terminal `aka attach` landing in that wait must
  // not be widened, narrowed or emptied by a decision made about the machine as
  // it was.
  const anotherAkaAttachesScoped = (): void => {
    writeControlPlaneCredential(settingsDir(akaHome()), {
      specVersion: 2,
      mode: 'scoped',
      endpoint: deployment.origin,
      apiKey: OTHER_AKA_KEY,
      mintedAt: '2026-10-07T00:00:00.000Z',
    });
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: deployment.origin, attachedAt: '2026-10-07T00:00:00.000Z' },
        attachmentScope: enrolledFor(deployment.origin),
      },
      akaHome(),
      null,
    );
  };

  /** What an older aka does to a personal device: a machine-wide key, the record left behind. */
  const olderAkaReattachesMachineWide = (): void => {
    writeControlPlaneCredential(settingsDir(akaHome()), {
      specVersion: 1,
      endpoint: deployment.origin,
      apiKey: OTHER_AKA_KEY,
      mintedAt: '2026-10-07T00:00:00.000Z',
    });
  };

  it.each([undefined, 'machine'] as const)(
    'writes nothing over a scoped credential another aka wrote, with the mode %s',
    async (mode) => {
      answerAs(deployment, ACCOUNT, ORGANIZATION, anotherAkaAttachesScoped);

      const res = await attachToControlPlane({
        endpoint: deployment.origin,
        accessKey: KEY,
        ...(mode === undefined ? {} : { mode }),
      });

      expect(res).toEqual({ ok: false, error: ATTACH_CHANGED_WHILE_WAITING });
      expectNoEchoOf(res.error, KEY);
      expect(deployment.received).toHaveLength(1);
      // Its credential and its enrolled list are exactly what it wrote.
      expect(storedCredential()).toMatchObject({
        specVersion: 2,
        mode: 'scoped',
        apiKey: OTHER_AKA_KEY,
      });
      expect(storedSettings().attachmentScope).toEqual(enrolledFor(deployment.origin));
    },
  );

  it('writes nothing when an older aka widens a personal device and no mode was named', async () => {
    await attachScoped();
    writeScope(enrolledFor(deployment.origin));
    answerAs(deployment, ACCOUNT, ORGANIZATION, olderAkaReattachesMachineWide);

    const res = await attachToControlPlane({ endpoint: deployment.origin, accessKey: ROTATED_KEY });

    // Kept mode was scoped when decided; the file now says machine-wide, so
    // neither mode can be written without somebody choosing it.
    expect(res).toEqual({ ok: false, error: ATTACH_CHANGED_WHILE_WAITING });
    expect(storedCredential()).toMatchObject({ specVersion: 1, apiKey: OTHER_AKA_KEY });
  });

  it('keeps the enrollments another aka made while the scoped mode was being attached', async () => {
    answerAs(deployment, ACCOUNT, ORGANIZATION, anotherAkaAttachesScoped);

    const res = await attachToControlPlane({
      endpoint: deployment.origin,
      accessKey: KEY,
      mode: 'scoped',
    });

    // Scoped over scoped for the same deployment is a key rotation, judged on the
    // file as it is when written: the list it holds is not replaced by an empty one.
    expect(res).toEqual({ ok: true });
    expect(storedCredential()).toMatchObject({ specVersion: 2, mode: 'scoped', apiKey: KEY });
    expect(storedSettings().attachmentScope).toEqual(enrolledFor(deployment.origin));
  });

  it('does not keep a bound record an older aka left beside its machine-wide key', async () => {
    await attachScoped();
    writeScope(enrolledFor(deployment.origin));
    answerAs(deployment, ACCOUNT, ORGANIZATION, olderAkaReattachesMachineWide);

    const res = await attachToControlPlane({
      endpoint: deployment.origin,
      accessKey: ROTATED_KEY,
      mode: 'scoped',
    });

    // The machine held a scoped credential when the key went out and a
    // machine-wide one when this wrote, so what is on file belongs to an
    // attachment that ended.
    expect(res).toEqual({ ok: true });
    expect(storedCredential()).toMatchObject({
      specVersion: 2,
      mode: 'scoped',
      apiKey: ROTATED_KEY,
    });
    expect(storedSettings().attachmentScope).toEqual(freshFor(deployment.origin));
  });

  it('reports a settings directory that became a file in the wait, and writes nothing', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('A file where the settings directory belongs reads as ENOTDIR on POSIX only');
      return;
    }
    answerAs(deployment, ACCOUNT, ORGANIZATION, () => {
      mkdirSync(akaHome(), { recursive: true });
      writeFileSync(settingsDir(akaHome()), 'not a directory');
    });

    const res = await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY });

    expect(res).toEqual({ ok: false, error: ATTACH_CREDENTIAL_UNWRITABLE });
    expect(readFileSync(settingsDir(akaHome()), 'utf8')).toBe('not a directory');
  });

  it('words the refusal so a person knows nothing was written and what to do', () => {
    expect(ATTACH_CHANGED_WHILE_WAITING).toMatch(/changed while/i);
    // Plain ASCII, like the other refusals beside it: no typographic apostrophe.
    expect(ATTACH_CHANGED_WHILE_WAITING).toContain("This machine's connection");
    expect(ATTACH_CHANGED_WHILE_WAITING).not.toContain(String.fromCharCode(0x2019));
    expect(ATTACH_CHANGED_WHILE_WAITING).toMatch(/nothing was written/i);
    expect(ATTACH_CHANGED_WHILE_WAITING).toMatch(/reload the page/i);
  });
});

describe('the history grant', () => {
  // A grant given while the machine is a personal device is for the history of
  // its enrolled repositories. Over a machine-wide credential the same grant
  // would send the history of activity from anywhere on the machine, and a grant names
  // its deployment, so one for another deployment would come back the day this
  // machine is attached there again.
  const grantFor = (endpoint: string): HistorySyncConsent => ({
    acknowledgedAt: '2026-10-01T00:00:00.000Z',
    payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
    endpoint,
  });
  const grantHistory = (endpoint: string): void => {
    applyOnboarding({ historySyncConsent: grantFor(endpoint) }, akaHome(), null);
  };

  it('is cleared when a personal device is widened to machine-wide', async () => {
    await attachScoped();
    grantHistory(deployment.origin);

    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });

    expect('historySyncConsent' in storedSettings()).toBe(false);
  });

  it('is cleared when a personal device is replaced by a machine-wide attach elsewhere', async () => {
    await attachScoped();
    grantHistory(deployment.origin);

    expect(
      await attachToControlPlane({ endpoint: other.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });

    expect('historySyncConsent' in storedSettings()).toBe(false);
  });

  it('is kept when a personal device rotates its key', async () => {
    await attachScoped();
    grantHistory(deployment.origin);

    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: ROTATED_KEY }),
    ).toEqual({ ok: true });

    expect(storedSettings().historySyncConsent).toEqual(grantFor(deployment.origin));
  });

  it('is kept when a machine-wide attachment rotates its key', async () => {
    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });
    grantHistory(deployment.origin);

    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: ROTATED_KEY }),
    ).toEqual({ ok: true });

    expect(storedSettings().historySyncConsent).toEqual(grantFor(deployment.origin));
  });

  it('is kept when a machine-wide attachment is narrowed to a personal device', async () => {
    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });
    grantHistory(deployment.origin);

    await attachScoped();

    expect(storedSettings().historySyncConsent).toEqual(grantFor(deployment.origin));
  });

  it('is kept when there was no credential before', async () => {
    // A grant with nothing under it is not a personal device's: nothing says it
    // was given for enrolled repositories only.
    grantHistory(deployment.origin);

    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });

    expect(storedSettings().historySyncConsent).toEqual(grantFor(deployment.origin));
  });

  it('is cleared when the widening was agreed to and an older aka writes a machine-wide key meanwhile', async () => {
    // The earlier read said personal device and the machine choice agreed to
    // widen it. By the time of the write an older aka has already made the key
    // machine-wide, so the file read then no longer says scoped. The grant was
    // still given to a personal device.
    await attachScoped();
    grantHistory(deployment.origin);
    answerAs(deployment, ACCOUNT, ORGANIZATION, () => {
      writeControlPlaneCredential(settingsDir(akaHome()), {
        specVersion: 1,
        endpoint: deployment.origin,
        apiKey: OTHER_AKA_KEY,
        mintedAt: '2026-10-07T00:00:00.000Z',
      });
    });

    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });

    expect(storedCredential()).toMatchObject({ specVersion: 1, apiKey: KEY });
    expect('historySyncConsent' in storedSettings()).toBe(false);
  });

  it('is cleared when a credential this build cannot read is replaced by a machine-wide one', async () => {
    // It may be a personal device's credential written by a newer build, and a
    // grant given to it was for enrolled repositories only.
    grantHistory(deployment.origin);
    writeFileSync(
      credentialFile(),
      JSON.stringify({
        specVersion: 3,
        mode: 'scoped',
        endpoint: deployment.origin,
        apiKey: OTHER_AKA_KEY,
      }),
      { mode: 0o600 },
    );

    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });

    expect(storedCredential()).toMatchObject({ specVersion: 1, apiKey: KEY });
    expect('historySyncConsent' in storedSettings()).toBe(false);
  });

  it('is cleared when a credential this build cannot read appears while the key is verified', async () => {
    // Nothing was on file when the mode was settled. A newer aka writes its
    // personal-device credential in the wait; the machine choice goes ahead over
    // it, and the later read is the only one that sees what is replaced.
    grantHistory(deployment.origin);
    answerAs(deployment, ACCOUNT, ORGANIZATION, () => {
      writeFileSync(
        credentialFile(),
        JSON.stringify({
          specVersion: 3,
          mode: 'scoped',
          endpoint: deployment.origin,
          apiKey: OTHER_AKA_KEY,
        }),
        { mode: 0o600 },
      );
    });

    expect(
      await attachToControlPlane({ endpoint: deployment.origin, accessKey: KEY, mode: 'machine' }),
    ).toEqual({ ok: true });

    expect(storedCredential()).toMatchObject({ specVersion: 1, apiKey: KEY });
    expect('historySyncConsent' in storedSettings()).toBe(false);
  });
});

describe('the refusal that asks for a mode', () => {
  it('tells a stale page what to do: reload, then choose the kind of device', () => {
    // The form sends no mode while the machine is managed, so a page rendered
    // then and submitted after the administrator's hold lifted meets this
    // refusal too, and has no choice on screen until it is reloaded.
    expect(ATTACH_MODE_REQUIRED).toMatch(/reload the page/i);
    expect(ATTACH_MODE_REQUIRED).toMatch(/personal or an organization device/i);
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
