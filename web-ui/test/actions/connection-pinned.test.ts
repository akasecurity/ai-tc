import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import {
  controlPlaneCredentialPath,
  dataDir,
  openLocalDatabase,
  readWorkspaceSettings,
  SETTINGS_FILENAME,
  settingsDir,
} from '@akasecurity/persistence';
import type { ManagedSettings } from '@akasecurity/schema';
import { MANAGED_SETTINGS_FILENAME } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../../../packages/persistence/src/managed-settings.ts';
import { attachToControlPlane, detachFromControlPlane } from '../../app/(app)/settings/actions.ts';
import { type LoopbackServer, startLoopbackServer } from '../helpers/loopback.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { tempHomes } from '../helpers/temp-home.ts';

// The dashboard's attach and detach actions on a machine an administrator
// governs — above all the shape a fleet kit ships: `runMode` and `controlPlane`
// PINNED with no lock. The settings writer refuses nothing for a pin, so an
// action that left the decision to the writer reported a detach as done on a
// machine that goes on reading as attached, and stored a credential for a
// deployment the settings never name again. Both actions now refuse ahead of
// every side effect, which is what each case below reads back: no request on
// either server, no credential, no settings write, no history window closed.
//
// The administrator is installed through the process-wide managed-settings
// seam, pointed at a file inside this test's own temp home. The machine's real
// managed file is never read: the setup file declares no administrator, and
// every case that wants one says so.
//
// Both deployments are real servers on loopback that accept any key, so an
// action that did NOT refuse would verify the key and write — a refusal is the
// only way a case below sees an empty `received`.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

// Homes are removed when this FILE finishes, not after each test. See the helper.
const newHome = tempHomes('aka-web-pinned-connection-');

/** A high-entropy key made at run time, so no key-shaped literal sits in the tree. */
const KEY = randomBytes(24).toString('base64url');

const ORGANIZATION = 'Example Org';

let home: string;
let pinned: LoopbackServer;
let other: LoopbackServer;

const akaHome = (): string => join(home, '.aka');
const credentialFile = (): string => controlPlaneCredentialPath(settingsDir(akaHome()));
const settingsFile = (): string => join(settingsDir(akaHome()), SETTINGS_FILENAME);

/** Accept every key, as a deployment that knows it would. */
function acceptAnyKey(server: LoopbackServer): void {
  server.reply((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        tenantName: ORGANIZATION,
        userEmail: 'operator',
        role: 'member',
        keyKind: 'plugin',
        serverTime: '2026-09-17T00:00:00.000Z',
      }),
    );
  });
}

/** Place an administrator's file inside this home and make it the one this process reads. */
function administer(overlay: ManagedSettings): void {
  const dir = join(home, 'administrator');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, MANAGED_SETTINGS_FILENAME);
  writeFileSync(file, JSON.stringify(overlay));
  UNSAFE_TEST_ONLY_setManagedSettingsPaths([file]);
}

/** The fleet-kit shape: mode and deployment pinned, nothing locked. */
function fleet(): ManagedSettings {
  return {
    specVersion: 1,
    organization: ORGANIZATION,
    values: {
      runMode: 'attached',
      controlPlane: { endpoint: pinned.origin, label: 'example-prod' },
    },
    lockedFields: [],
  };
}

function credentialEndpoint(): unknown {
  const parsed = JSON.parse(readFileSync(credentialFile(), 'utf8')) as { endpoint?: unknown };
  return parsed.endpoint;
}

function freezeHistoryBoundary(): void {
  const db = openLocalDatabase(dataDir(akaHome()));
  try {
    db.historySync.rearmFor('some-fingerprint', Date.parse('2026-08-01T00:00:00.000Z'));
  } finally {
    db.close();
  }
}

function historyBoundaryFrozen(): boolean {
  const db = openLocalDatabase(dataDir(akaHome()));
  try {
    return db.historySync.deployment().backlogBefore !== undefined;
  } finally {
    db.close();
  }
}

beforeEach(async () => {
  home = newHome();
  osHome.dir = home;
  pinned = await startLoopbackServer();
  other = await startLoopbackServer();
  acceptAnyKey(pinned);
  acceptAnyKey(other);
});

afterEach(async () => {
  // Back to the setup file's declaration: no administrator.
  UNSAFE_TEST_ONLY_setManagedSettingsPaths([]);
  await Promise.all([pinned.close(), other.close()]);
});

describe('attachToControlPlane on a governed machine', () => {
  it('still attaches to the pinned endpoint — that is the enrolment path', async () => {
    administer(fleet());
    const res = await attachToControlPlane({ endpoint: pinned.origin, accessKey: KEY });
    expect(res).toEqual({ ok: true });
    expect(pinned.received).toHaveLength(1);
    expect(credentialEndpoint()).toBe(pinned.origin);
  });

  it('refuses to attach elsewhere before the key is sent, naming who pinned it and where', async () => {
    administer(fleet());
    const res = await attachToControlPlane({ endpoint: other.origin, accessKey: KEY });

    expect(res.ok).toBe(false);
    expect(res.error).toContain(ORGANIZATION);
    expect(res.error).toContain(pinned.origin);
    expectNoEchoOf(res.error, KEY);
    expect(other.received).toEqual([]);
    expect(pinned.received).toEqual([]);
    expect(existsSync(credentialFile())).toBe(false);
    expect(existsSync(settingsFile())).toBe(false);
  });

  it('refuses a name that differs from the pinned one, before the key is sent', async () => {
    administer(fleet());
    const res = await attachToControlPlane({
      endpoint: pinned.origin,
      label: 'renamed-here',
      accessKey: KEY,
    });

    expect(res).toEqual({
      ok: false,
      error: `${ORGANIZATION} manages this machine name, so it cannot be renamed here.`,
    });
    expect(pinned.received).toEqual([]);
    expect(existsSync(credentialFile())).toBe(false);
  });

  it('accepts a name equal to the pinned one — the refusal is about the difference', async () => {
    administer(fleet());
    const res = await attachToControlPlane({
      endpoint: pinned.origin,
      label: 'example-prod',
      accessKey: KEY,
    });
    expect(res).toEqual({ ok: true });
    expect(credentialEndpoint()).toBe(pinned.origin);
  });

  it.each<[string, (endpoint: string) => ManagedSettings]>([
    [
      'pinned',
      (endpoint) => ({
        specVersion: 1,
        organization: ORGANIZATION,
        values: { runMode: 'standalone', controlPlane: { endpoint } },
        lockedFields: [],
      }),
    ],
    [
      'locked',
      () => ({
        specVersion: 1,
        organization: ORGANIZATION,
        values: {},
        lockedFields: ['runMode'],
      }),
    ],
  ])(
    'refuses any attach on a machine whose mode is %s to standalone, before the key is sent',
    async (_how, overlay) => {
      administer(overlay(pinned.origin));
      const res = await attachToControlPlane({ endpoint: pinned.origin, accessKey: KEY });

      expect(res).toEqual({
        ok: false,
        error: `${ORGANIZATION} manages this machine and has set it to standalone, so it cannot be attached here.`,
      });
      expect(pinned.received).toEqual([]);
      expect(existsSync(credentialFile())).toBe(false);
    },
  );

  describe('under a lock, the name the connection already has', () => {
    // Attached and named unmanaged first, because a lock with no value freezes
    // whatever the user last chose. That attach is the one request the server
    // has seen when each case begins.
    beforeEach(async () => {
      expect(
        await attachToControlPlane({ endpoint: pinned.origin, label: 'Old', accessKey: KEY }),
      ).toEqual({ ok: true });
      administer({
        specVersion: 1,
        organization: ORGANIZATION,
        values: {},
        lockedFields: ['runMode'],
      });
    });

    it('refuses leaving the name off before the key is sent, and says how to keep it', async () => {
      const res = await attachToControlPlane({ endpoint: pinned.origin, accessKey: KEY });

      expect(res).toEqual({
        ok: false,
        error: `${ORGANIZATION} manages this machine name, so it cannot be renamed here. Attach with the name it already has, as this page shows it.`,
      });
      expect(pinned.received).toHaveLength(1);
      expect(readWorkspaceSettings(akaHome()).controlPlane?.label).toBe('Old');
    });

    it('refuses a rename before the key is sent', async () => {
      const res = await attachToControlPlane({
        endpoint: pinned.origin,
        label: 'New',
        accessKey: KEY,
      });

      expect(res).toEqual({
        ok: false,
        error: `${ORGANIZATION} manages this machine name, so it cannot be renamed here.`,
      });
      expect(pinned.received).toHaveLength(1);
    });

    it('lets a re-attach keep the name it has — how a key is rotated under a lock', async () => {
      const res = await attachToControlPlane({
        endpoint: pinned.origin,
        label: 'Old',
        accessKey: KEY,
      });

      expect(res).toEqual({ ok: true });
      expect(pinned.received).toHaveLength(2);
    });
  });

  it('lets an unmanaged machine move to a different deployment', async () => {
    // The positive control: the refusals above come from the administrator's
    // file, not from the user's own descriptor naming a deployment already.
    expect(await attachToControlPlane({ endpoint: pinned.origin, accessKey: KEY })).toEqual({
      ok: true,
    });
    expect(await attachToControlPlane({ endpoint: other.origin, accessKey: KEY })).toEqual({
      ok: true,
    });
    expect(other.received).toHaveLength(1);
    expect(readWorkspaceSettings(akaHome()).controlPlane?.endpoint).toBe(other.origin);
    expect(credentialEndpoint()).toBe(other.origin);
  });
});

describe('detachFromControlPlane on a governed machine', () => {
  it('refuses to detach under a fleet pin, naming who pinned it and where, and changes nothing', async () => {
    administer(fleet());
    expect(await attachToControlPlane({ endpoint: pinned.origin, accessKey: KEY })).toEqual({
      ok: true,
    });
    const settingsBefore = readFileSync(settingsFile(), 'utf8');

    const res = await detachFromControlPlane();

    expect(res.ok).toBe(false);
    expect(res.error).toContain(ORGANIZATION);
    expect(res.error).toContain(pinned.origin);
    expect(credentialEndpoint()).toBe(pinned.origin);
    expect(readFileSync(settingsFile(), 'utf8')).toBe(settingsBefore);
  });

  it('refuses to detach a machine that never attached, since the pin is what it reads', async () => {
    administer(fleet());
    const res = await detachFromControlPlane();

    expect(res.ok).toBe(false);
    expect(res.error).toContain(pinned.origin);
    expect(existsSync(settingsFile())).toBe(false);
  });

  it('refuses before the history window is closed, so a refused detach releases nothing', async () => {
    administer(fleet());
    expect(await attachToControlPlane({ endpoint: pinned.origin, accessKey: KEY })).toEqual({
      ok: true,
    });
    freezeHistoryBoundary();

    expect((await detachFromControlPlane()).ok).toBe(false);
    expect(historyBoundaryFrozen()).toBe(true);
  });

  it('refuses a lock with no pin the same way, ahead of the history window', async () => {
    // Attached unmanaged first: a lock with no value freezes whatever the user
    // last chose. The lock used to be refused by the writer, AFTER the history
    // window had been handed over for a detach that then did not happen.
    expect(await attachToControlPlane({ endpoint: pinned.origin, accessKey: KEY })).toEqual({
      ok: true,
    });
    freezeHistoryBoundary();
    administer({
      specVersion: 1,
      organization: ORGANIZATION,
      values: {},
      lockedFields: ['runMode'],
    });

    const res = await detachFromControlPlane();

    expect(res.ok).toBe(false);
    expect(res.error).toContain(ORGANIZATION);
    expect(res.error).toContain(pinned.origin);
    expect(historyBoundaryFrozen()).toBe(true);
    expect(readWorkspaceSettings(akaHome()).runMode).toBe('attached');
    expect(credentialEndpoint()).toBe(pinned.origin);
  });

  it('lets a detach land under a pin on the descriptor alone, and that detach releases the window', async () => {
    // The positive control for the two cases above: with `runMode` neither
    // pinned nor locked, a cleared file reads back as standalone, so the detach
    // is the user's to make — and a detach that lands DOES close the window,
    // which is what makes "still frozen" above mean something.
    administer({
      specVersion: 1,
      organization: ORGANIZATION,
      values: { controlPlane: { endpoint: pinned.origin, label: 'example-prod' } },
      lockedFields: [],
    });
    expect(await attachToControlPlane({ endpoint: pinned.origin, accessKey: KEY })).toEqual({
      ok: true,
    });
    freezeHistoryBoundary();

    expect(await detachFromControlPlane()).toEqual({ ok: true });
    expect(readWorkspaceSettings(akaHome()).runMode).toBe('standalone');
    expect(existsSync(credentialFile())).toBe(false);
    expect(historyBoundaryFrozen()).toBe(false);
  });

  it('lets a detach through where the overlay holds the machine standalone', async () => {
    administer({
      specVersion: 1,
      organization: ORGANIZATION,
      values: { runMode: 'standalone', controlPlane: { endpoint: pinned.origin } },
      lockedFields: [],
    });
    expect(await detachFromControlPlane()).toEqual({ ok: true });
  });
});
