import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import { controlPlaneCredentialPath, settingsDir } from '@akasecurity/persistence';
import type { HistorySyncConsent, ManagedSettings } from '@akasecurity/schema';
import {
  HISTORY_SYNC_PAYLOAD_VERSION,
  MANAGED_SETTINGS_FILENAME,
  resolveScope,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../../../packages/persistence/src/managed-settings.ts';
import { attachToControlPlane } from '../../app/(app)/settings/actions.ts';
import {
  ATTACH_CREDENTIAL_NOT_SAVED_AFTER_SETTINGS,
  managedRefusal,
  SETTINGS_WRITE_ERROR,
} from '../../app/lib/action-refusals.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { tempHomes } from '../helpers/temp-home.ts';

// The order of the dashboard attach's two writes, which is the order `aka attach`
// uses (`writesSettingsFirst`, shared through the persistence package). The
// credential goes first unless that could leave the new credential beside an
// enrolled list or a history grant the finished attach replaces; there the
// settings go first, so a stop between the two leaves what the machine had beside
// no list (machine-wide) or an empty one (scoped), which sends no repository's
// activity. The one exception is a scoped attach over a usable machine-wide
// credential, which writes the credential first as well, as `aka attach` does: a
// stop there leaves the new scoped key beside the list on file, which may belong
// to another organization or account, and the earlier grant. The writes are
// counted and can be made to fail, and a hook runs just before the settings write
// to read what is on disk at that moment.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
const stand = vi.hoisted(() => ({
  who: { tenantName: 'Example Org', userEmail: 'operator' },
  failSettingsWrite: false,
  failCredentialWriteAt: undefined as number | undefined,
  beforeNextSettingsWrite: undefined as (() => void) | undefined,
  credentialWrites: 0,
  settingsWrites: 0,
  revalidated: [] as string[],
}));
vi.mock('next/cache', () => ({
  revalidatePath: (path: string) => {
    stand.revalidated.push(path);
  },
}));
// The transport, stubbed: the key is accepted as `stand.who` and nothing reaches a socket.
vi.mock('@akasecurity/remote', () => ({
  createRemoteClient: () => ({ whoami: () => Promise.resolve({ ...stand.who }) }),
}));
vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    applyOnboarding: (
      ...args: Parameters<typeof actual.applyOnboarding>
    ): ReturnType<typeof actual.applyOnboarding> => {
      stand.settingsWrites += 1;
      if (stand.failSettingsWrite) throw new Error('settings write failed');
      // One shot, cleared before it runs, so the write it makes reaches the real one.
      const racing = stand.beforeNextSettingsWrite;
      stand.beforeNextSettingsWrite = undefined;
      racing?.();
      return actual.applyOnboarding(...args);
    },
    writeControlPlaneCredential: (
      ...args: Parameters<typeof actual.writeControlPlaneCredential>
    ): void => {
      stand.credentialWrites += 1;
      if (stand.failCredentialWriteAt === stand.credentialWrites) {
        throw new Error('credential write failed');
      }
      actual.writeControlPlaneCredential(...args);
    },
  };
});
// The real writers, for arranging a machine without touching the counters.
const real = await vi.importActual<typeof Persistence>('@akasecurity/persistence');

// Homes are removed when this FILE finishes, not after each test. See the helper.
const newHome = tempHomes('aka-web-attach-order-');

/** High-entropy keys made at run time, so no key-shaped literal sits in the tree. */
const KEY = randomBytes(24).toString('base64url');
const OLD_KEY = randomBytes(24).toString('base64url');

const ENDPOINT = 'https://aka.example.com';
const OTHER_ENDPOINT = 'https://aka.example.net';
const ISO = '2026-10-01T00:00:00.000Z';
const DEFAULT_WHO = { tenantName: 'Example Org', userEmail: 'operator' };

const ENTRY = { kind: 'repo', identity: 'github.com/acme/payments-api', enrolledAt: ISO };
/** A list bound to the organization and account the key verifies as by default. */
const BOUND = { ...DEFAULT_WHO, endpoint: ENDPOINT, entries: [ENTRY] };
/** A list that names no account. */
const UNBOUND = { endpoint: ENDPOINT, entries: [ENTRY] };
const GRANT: HistorySyncConsent = {
  acknowledgedAt: ISO,
  payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
  endpoint: ENDPOINT,
};
/** The empty list a scoped attach writes for whoever the key verified as. */
const FRESH = (who: { tenantName: string; userEmail: string }): object => ({
  endpoint: ENDPOINT,
  tenantName: who.tenantName,
  userEmail: who.userEmail,
  entries: [],
});

let home: string;

const akaHome = (): string => join(home, '.aka');
const credentialFile = (): string => controlPlaneCredentialPath(settingsDir(akaHome()));
const settingsFile = (): string => join(settingsDir(akaHome()), 'settings.json');

beforeEach(() => {
  home = newHome();
  osHome.dir = home;
  stand.who = { ...DEFAULT_WHO };
  stand.failSettingsWrite = false;
  stand.failCredentialWriteAt = undefined;
  stand.beforeNextSettingsWrite = undefined;
  stand.credentialWrites = 0;
  stand.settingsWrites = 0;
  stand.revalidated = [];
});

afterEach(() => {
  // Back to the setup file's declaration: no administrator.
  UNSAFE_TEST_ONLY_setManagedSettingsPaths([]);
});

interface Stored {
  attachmentScope?: unknown;
  historySyncConsent?: HistorySyncConsent;
}

/** Attached settings with what the stored list and grant are, written without touching the counters. */
function attachedSettings(extra: Stored, endpoint = ENDPOINT): void {
  real.applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint, attachedAt: ISO }, ...extra },
    akaHome(),
    null,
  );
}

function scopedCredential(endpoint = ENDPOINT): void {
  real.writeControlPlaneCredential(settingsDir(akaHome()), {
    specVersion: 2,
    mode: 'scoped',
    endpoint,
    apiKey: OLD_KEY,
    mintedAt: ISO,
  });
}

function machineCredential(endpoint = ENDPOINT): void {
  real.writeControlPlaneCredential(settingsDir(akaHome()), {
    specVersion: 1,
    endpoint,
    apiKey: OLD_KEY,
    mintedAt: ISO,
  });
}

/** A credential file from a newer build, which this one cannot read. Returns its text. */
function plantUnreadable(): string {
  mkdirSync(settingsDir(akaHome()), { recursive: true, mode: 0o700 });
  const content = JSON.stringify({
    specVersion: 3,
    mode: 'scoped',
    endpoint: ENDPOINT,
    apiKey: OLD_KEY,
  });
  writeFileSync(credentialFile(), content, { mode: 0o600 });
  return content;
}

/** The credential file's text, or 'absent'. */
function credentialText(): string {
  return existsSync(credentialFile()) ? readFileSync(credentialFile(), 'utf8') : 'absent';
}

function storedCredential(): Record<string, unknown> {
  return JSON.parse(readFileSync(credentialFile(), 'utf8')) as Record<string, unknown>;
}

/** The user's own settings file, raw. */
function storedSettings(): Record<string, unknown> {
  return JSON.parse(readFileSync(settingsFile(), 'utf8')) as Record<string, unknown>;
}

/** Records the credential file's text at the moment of the next settings write. */
function credentialAtSettingsWrite(): { ran: () => boolean; text: () => string | undefined } {
  let ran = false;
  let seen: string | undefined;
  stand.beforeNextSettingsWrite = () => {
    ran = true;
    seen = credentialText();
  };
  return { ran: () => ran, text: () => seen };
}

/** Records the key the credential on disk holds at the next settings write, or 'absent'. */
function keyAtSettingsWrite(): { get: () => string | undefined } {
  const watch = credentialAtSettingsWrite();
  return {
    get: () => {
      const text = watch.text();
      if (text === undefined || text === 'absent') return text;
      return (JSON.parse(text) as { apiKey?: string }).apiKey;
    },
  };
}

/** Place an administrator's file inside this home and make it the one this process reads. */
function administer(overlay: ManagedSettings): void {
  const dir = join(home, 'administrator');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, MANAGED_SETTINGS_FILENAME);
  writeFileSync(file, JSON.stringify(overlay));
  UNSAFE_TEST_ONLY_setManagedSettingsPaths([file]);
}

const lockMode = (): ManagedSettings => ({
  specVersion: 1,
  organization: 'Example Org',
  values: {},
  lockedFields: ['runMode'],
});

const attachMachine = (): ReturnType<typeof attachToControlPlane> =>
  attachToControlPlane({ endpoint: ENDPOINT, accessKey: KEY, mode: 'machine' });
const attachScoped = (): ReturnType<typeof attachToControlPlane> =>
  attachToControlPlane({ endpoint: ENDPOINT, accessKey: KEY, mode: 'scoped' });

/** What the forward verdict reads of what is left: a scoped credential and no repository enrolled. */
const nothingEnrolled = (): ReturnType<typeof resolveScope> =>
  resolveScope({ mode: 'scoped', scope: storedSettings().attachmentScope, endpoint: ENDPOINT });

describe('a machine-wide attach over a personal device writes the settings first', () => {
  // The settings drop the enrolled list and the history grant; the credential that
  // follows makes the machine machine-wide. A stop between the two must leave the
  // personal device's credential beside no list and no grant, never a machine-wide
  // credential beside them.
  const arrangePersonalDevice = (): void => {
    scopedCredential();
    attachedSettings({ attachmentScope: BOUND, historySyncConsent: GRANT });
  };

  it('finds the personal device credential still in place when it writes the settings', async () => {
    arrangePersonalDevice();
    const before = credentialText();
    const watch = credentialAtSettingsWrite();

    expect(await attachMachine()).toEqual({ ok: true });

    expect(watch.ran()).toBe(true);
    expect(watch.text()).toBe(before);
    expect(storedCredential()).toMatchObject({ specVersion: 1, apiKey: KEY });
    expect(storedSettings()).not.toHaveProperty('attachmentScope');
    expect(storedSettings()).not.toHaveProperty('historySyncConsent');
    expect(stand.settingsWrites).toBe(1);
  });

  it('leaves the personal device sending no repository activity, and says so, when the credential write fails after the settings', async () => {
    arrangePersonalDevice();
    const before = credentialText();
    stand.failCredentialWriteAt = 1;

    const res = await attachMachine();

    expect(res).toEqual({ ok: false, error: ATTACH_CREDENTIAL_NOT_SAVED_AFTER_SETTINGS });
    expectNoEchoOf(res.error, KEY);
    expect(credentialText()).toBe(before);
    expect(storedSettings()).not.toHaveProperty('attachmentScope');
    expect(storedSettings()).not.toHaveProperty('historySyncConsent');
    expect(storedSettings().runMode).toBe('attached');
    expect(nothingEnrolled()).toEqual({ mode: 'scoped', keys: new Set() });
    expect(stand.revalidated).toEqual(['/settings']);
    expect(stand.settingsWrites).toBe(1);
  });

  it('leaves a credential file it cannot read in place, and says so, when the credential write fails after the settings', async () => {
    const planted = plantUnreadable();
    attachedSettings({ attachmentScope: BOUND, historySyncConsent: GRANT });
    stand.failCredentialWriteAt = 1;

    const res = await attachMachine();

    expect(res).toEqual({ ok: false, error: ATTACH_CREDENTIAL_NOT_SAVED_AFTER_SETTINGS });
    expect(readFileSync(credentialFile(), 'utf8')).toBe(planted);
    expect(storedSettings()).not.toHaveProperty('attachmentScope');
    expect(storedSettings()).not.toHaveProperty('historySyncConsent');
    expect(stand.settingsWrites).toBe(1);
  });

  it('leaves the machine as it was when the settings write fails first', async () => {
    arrangePersonalDevice();
    const credentialBefore = credentialText();
    const settingsBefore = readFileSync(settingsFile(), 'utf8');
    stand.failSettingsWrite = true;

    const res = await attachMachine();

    // Nothing was written ahead of it, so there is nothing to put back and nothing to add.
    expect(res).toEqual({ ok: false, error: SETTINGS_WRITE_ERROR });
    expect(stand.credentialWrites).toBe(0);
    expect(credentialText()).toBe(credentialBefore);
    expect(readFileSync(settingsFile(), 'utf8')).toBe(settingsBefore);
  });

  it('answers a lock that lands as the settings are written with its sentence, and writes no credential', async () => {
    // A half-attached machine: a personal device's credential and no settings file.
    scopedCredential();
    const before = credentialText();
    stand.beforeNextSettingsWrite = () => {
      administer(lockMode());
    };

    const res = await attachMachine();

    expect(res).toEqual({ ok: false, error: managedRefusal(['runMode']) });
    expect(stand.credentialWrites).toBe(0);
    expect(credentialText()).toBe(before);
  });

  // The credential file is gone but the settings still say attached to this
  // endpoint, with a list or a history grant: a deleted credential file leaves
  // them so, and so does a rollback that reports a file it could not read as gone.
  // The credential written first would sit beside them as a machine-wide one.
  describe('over settings that still carry a list or a grant, with no credential file', () => {
    const STALE = [
      ['a list and a grant', { attachmentScope: BOUND, historySyncConsent: GRANT }],
      ['a list alone', { attachmentScope: BOUND }],
      ['a grant alone', { historySyncConsent: GRANT }],
    ] as const satisfies readonly (readonly [string, Stored])[];

    it.each(STALE)(
      'finds no credential file yet when it writes the settings, with %s',
      async (_name, stale) => {
        attachedSettings(stale);
        const watch = credentialAtSettingsWrite();

        expect(await attachMachine()).toEqual({ ok: true });

        expect(watch.ran()).toBe(true);
        expect(watch.text()).toBe('absent');
        expect(storedCredential()).toMatchObject({ specVersion: 1, apiKey: KEY });
        expect(storedSettings()).not.toHaveProperty('attachmentScope');
        expect(stand.settingsWrites).toBe(1);
      },
    );

    it('leaves no list and no credential, and says so, when the credential write fails after the settings', async () => {
      attachedSettings({ attachmentScope: BOUND, historySyncConsent: GRANT });
      stand.failCredentialWriteAt = 1;

      const res = await attachMachine();

      expect(res).toEqual({ ok: false, error: ATTACH_CREDENTIAL_NOT_SAVED_AFTER_SETTINGS });
      expect(credentialText()).toBe('absent');
      expect(storedSettings()).not.toHaveProperty('attachmentScope');
      expect(stand.settingsWrites).toBe(1);
    });

    it('leaves everything untouched when the settings write fails first', async () => {
      attachedSettings({ attachmentScope: BOUND, historySyncConsent: GRANT });
      const settingsBefore = readFileSync(settingsFile(), 'utf8');
      stand.failSettingsWrite = true;

      const res = await attachMachine();

      expect(res).toEqual({ ok: false, error: SETTINGS_WRITE_ERROR });
      expect(stand.credentialWrites).toBe(0);
      expect(readFileSync(settingsFile(), 'utf8')).toBe(settingsBefore);
      expect(credentialText()).toBe('absent');
    });
  });

  // The order changes only where a stop between the writes could put a
  // machine-wide credential beside a list or grant given for a personal device.
  describe('and keeps the credential first everywhere else', () => {
    it('writes the credential first on a machine that was always machine-wide, grant and all', async () => {
      machineCredential();
      attachedSettings({ historySyncConsent: GRANT });
      const seen = keyAtSettingsWrite();

      expect(await attachMachine()).toEqual({ ok: true });

      expect(seen.get()).toBe(KEY);
    });

    it('writes the credential first on a first attach to a clean machine', async () => {
      const seen = keyAtSettingsWrite();

      expect(await attachMachine()).toEqual({ ok: true });

      expect(seen.get()).toBe(KEY);
    });

    it('writes the credential first when settings that carry nothing are all that is left', async () => {
      attachedSettings({});
      const seen = keyAtSettingsWrite();

      expect(await attachMachine()).toEqual({ ok: true });

      expect(seen.get()).toBe(KEY);
    });

    it('answers a lock that lands as the settings are written with its sentence, and removes the key it wrote', async () => {
      stand.beforeNextSettingsWrite = () => {
        administer(lockMode());
      };

      const res = await attachMachine();

      expect(res).toEqual({ ok: false, error: managedRefusal(['runMode']) });
      // The key was written first, before the settings refused, and is gone again:
      // without the count, an attach that never wrote one would pass as well.
      expect(stand.credentialWrites).toBe(1);
      expect(existsSync(credentialFile())).toBe(false);
    });
  });
});

// A scoped attach keeps the list it finds only on a rotation: the same
// deployment, the same organization and account. Any other scoped attach writes a
// fresh empty list over whatever is stored, and the credential written first would
// sit beside the old list until the settings follow.
describe('a scoped attach that will not keep the stored list writes the settings first', () => {
  interface NotKept {
    name: string;
    /** Puts the machine in a state whose stored list this attach will not keep. */
    arrange: () => void;
    /** Who the key verifies as. */
    who: { tenantName: string; userEmail: string };
  }
  const STALE: Stored = { attachmentScope: BOUND, historySyncConsent: GRANT };
  const NOT_KEPT: NotKept[] = [
    {
      name: 'a credential for this deployment, with the key verified as another account',
      arrange: () => {
        scopedCredential();
        attachedSettings(STALE);
      },
      who: { tenantName: 'Example Org', userEmail: 'someone-else' },
    },
    {
      name: 'a credential for another deployment',
      arrange: () => {
        scopedCredential(OTHER_ENDPOINT);
        attachedSettings(
          { attachmentScope: { ...BOUND, endpoint: OTHER_ENDPOINT }, historySyncConsent: GRANT },
          OTHER_ENDPOINT,
        );
      },
      who: DEFAULT_WHO,
    },
    {
      name: 'a list that names no account',
      arrange: () => {
        scopedCredential();
        attachedSettings({ attachmentScope: UNBOUND, historySyncConsent: GRANT });
      },
      who: DEFAULT_WHO,
    },
    {
      name: 'no credential file',
      arrange: () => {
        attachedSettings(STALE);
      },
      who: DEFAULT_WHO,
    },
    {
      name: 'a credential file this build cannot read',
      arrange: () => {
        plantUnreadable();
        attachedSettings(STALE);
      },
      who: DEFAULT_WHO,
    },
  ];

  // This surface's scoped attach leaves the history grant as it is, where
  // `aka attach` spells this run's history answer on every attach, so the grant is
  // not asserted in these rows.
  it.for(NOT_KEPT)(
    'finds the earlier credential still in place when it writes the settings, over $name',
    async (row) => {
      row.arrange();
      stand.who = row.who;
      const before = credentialText();
      const watch = credentialAtSettingsWrite();

      expect(await attachScoped()).toEqual({ ok: true });

      expect(watch.ran()).toBe(true);
      expect(watch.text()).toBe(before);
      expect(storedCredential()).toMatchObject({ specVersion: 2, mode: 'scoped', apiKey: KEY });
      expect(storedSettings().attachmentScope).toEqual(FRESH(row.who));
      expect(stand.settingsWrites).toBe(1);
    },
  );

  it.for(NOT_KEPT)(
    'leaves the earlier credential beside an empty list, and says so, when the credential write fails after the settings, over $name',
    async (row) => {
      row.arrange();
      stand.who = row.who;
      const before = credentialText();
      stand.failCredentialWriteAt = 1;

      const res = await attachScoped();

      expect(res).toEqual({ ok: false, error: ATTACH_CREDENTIAL_NOT_SAVED_AFTER_SETTINGS });
      expect(credentialText()).toBe(before);
      expect(nothingEnrolled()).toEqual({ mode: 'scoped', keys: new Set() });
      expect(stand.settingsWrites).toBe(1);
    },
  );

  it.for(NOT_KEPT)(
    'leaves the machine as it was when the settings write fails first, over $name',
    async (row) => {
      row.arrange();
      stand.who = row.who;
      const credentialBefore = credentialText();
      const settingsBefore = readFileSync(settingsFile(), 'utf8');
      stand.failSettingsWrite = true;

      const res = await attachScoped();

      expect(res).toEqual({ ok: false, error: SETTINGS_WRITE_ERROR });
      expect(stand.credentialWrites).toBe(0);
      expect(credentialText()).toBe(credentialBefore);
      expect(readFileSync(settingsFile(), 'utf8')).toBe(settingsBefore);
    },
  );

  describe('and keeps the credential first everywhere else', () => {
    it('writes the credential first on a rotation that keeps the list', async () => {
      scopedCredential();
      attachedSettings(STALE);
      const seen = keyAtSettingsWrite();

      expect(await attachScoped()).toEqual({ ok: true });

      expect(seen.get()).toBe(KEY);
      expect(storedSettings().attachmentScope).toEqual(BOUND);
    });

    it('writes the credential first on a first scoped attach with nothing stored', async () => {
      const seen = keyAtSettingsWrite();

      expect(await attachScoped()).toEqual({ ok: true });

      expect(seen.get()).toBe(KEY);
    });

    it('writes the credential first when the settings that are left carry neither a list nor a grant', async () => {
      attachedSettings({});
      const seen = keyAtSettingsWrite();

      expect(await attachScoped()).toEqual({ ok: true });

      expect(seen.get()).toBe(KEY);
    });

    // The exception, taken for parity with `aka attach` alone. This surface asks
    // no history question, and its scoped attach keeps the grant already stored,
    // so settings first would be harmless here. A stop between the writes leaves
    // the new scoped key beside the list on file, which may be another account's
    // and, if it names this deployment, forwards under the new key until the
    // machine is attached again.
    it('writes the credential first over a machine-wide credential, whatever settings are stored', async () => {
      machineCredential();
      attachedSettings(STALE);
      const seen = keyAtSettingsWrite();

      expect(await attachScoped()).toEqual({ ok: true });

      expect(seen.get()).toBe(KEY);
      expect(storedSettings().attachmentScope).toEqual(FRESH(DEFAULT_WHO));
    });
  });
});

describe('what an attach whose credential was not saved after its settings says', () => {
  it('says what was saved, what is not sent, and to attach again before enrolling, naming no command', () => {
    expect(ATTACH_CREDENTIAL_NOT_SAVED_AFTER_SETTINGS).toBe(
      "The settings were saved, but the access key could not be saved to ~/.aka/settings, so the attach did not finish. The enrolled list is cleared, and no repository's activity is sent until this machine is attached again. Attach it again before enrolling a repository.",
    );
    // No backtick, so no command is named: a machine an administrator governs
    // attaches from this page or a terminal.
    expect(ATTACH_CREDENTIAL_NOT_SAVED_AFTER_SETTINGS).not.toContain('`');
    // Plain ASCII, like the refusals beside it: no typographic apostrophe.
    expect(ATTACH_CREDENTIAL_NOT_SAVED_AFTER_SETTINGS).not.toContain(String.fromCharCode(0x2019));
  });
});
