import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { ManagedContext, ManagedSettings, WorkspaceSettings } from '@akasecurity/schema';
import {
  defaultWorkspaceSettings,
  isFieldManaged,
  MANAGED_SETTINGS_FILENAME,
  managedByLabel,
  ManagedSettingKey,
  MODEL_JUDGE_PAYLOAD_VERSION,
  VAULT_CONSENT_VERSION,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  lockedAmong,
  managedContextOf,
  managedSettingsPaths,
  overlayManagedSettings,
  readManagedSettings,
} from '../src/managed-settings.ts';
import {
  applyOnboarding,
  ManagedFieldError,
  readEffectiveSettings,
  readWorkspaceSettings,
} from '../src/settings.ts';

// Administrative configuration is a file AKA reads and never writes, so every
// case here works by putting a file somewhere and asking what the product then
// believes. Nothing is mocked: the reader takes its search paths as an argument
// precisely so a temp dir can stand in for the real system locations.

let base: string;
let managedDir: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-managed-'));
  managedDir = mkdtempSync(join(tmpdir(), 'aka-managed-src-'));
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
  rmSync(managedDir, { recursive: true, force: true });
});

function managedFile(): string {
  return join(managedDir, MANAGED_SETTINGS_FILENAME);
}

function writeManaged(contents: unknown, dir = managedDir): string {
  mkdirSync(dir, { recursive: true });
  const file = join(dir, MANAGED_SETTINGS_FILENAME);
  writeFileSync(file, JSON.stringify(contents));
  return file;
}

function settings(overrides: Partial<WorkspaceSettings> = {}): WorkspaceSettings {
  return { ...defaultWorkspaceSettings(), ...overrides };
}

describe('managedSettingsPaths — where an administrator puts the file', () => {
  it('points outside the user home on every platform', () => {
    // A path inside ~ would make a lock removable by the party being locked.
    for (const platform of ['darwin', 'win32', 'linux'] as const) {
      const paths = managedSettingsPaths(platform);
      expect(paths.length).toBeGreaterThan(0);
      for (const p of paths) {
        expect(p).toContain(MANAGED_SETTINGS_FILENAME);
        expect(p).not.toContain('.aka');
      }
    }
  });

  it('gives each platform its own conventional administrative root', () => {
    // The FULL list per platform, not just the first entry. macOS has two, and
    // asserting only index 0 left the second location documented nowhere and
    // pinned by nothing — which is how it went missing from CLAUDE.md.
    expect(managedSettingsPaths('darwin')).toEqual([
      '/Library/Application Support/AKASecurity/managed-settings.json',
      '/Library/Managed Preferences/managed-settings.json',
    ]);
    expect(managedSettingsPaths('win32')).toEqual([
      'C:\\ProgramData\\AKASecurity\\managed-settings.json',
    ]);
    expect(managedSettingsPaths('linux')).toEqual(['/etc/aka/managed-settings.json']);
  });
});

describe('readManagedSettings — fail-open on a damaged administrative file', () => {
  it('returns null when no administrator has placed a file', () => {
    expect(readManagedSettings([join(managedDir, MANAGED_SETTINGS_FILENAME)])).toBeNull();
  });

  it('reads a well-formed file', () => {
    writeManaged({ organization: 'Acme', lockedFields: ['runMode'] });
    const managed = readManagedSettings([join(managedDir, MANAGED_SETTINGS_FILENAME)]);
    expect(managed?.organization).toBe('Acme');
    expect(managed?.lockedFields).toEqual(['runMode']);
  });

  it('runs UNMANAGED rather than refusing when the file is malformed', () => {
    // The posture cuts one way and it is deliberate: a typo in an MDM payload
    // must not break every hook on every managed machine at once. Stated as
    // behaviour so a later change to fail closed is a decision, not a slip.
    writeManaged('not an object');
    expect(readManagedSettings([join(managedDir, MANAGED_SETTINGS_FILENAME)])).toBeNull();
  });

  it('skips a file whose shape fails the schema', () => {
    writeManaged({ lockedFields: ['notASetting'] });
    expect(readManagedSettings([join(managedDir, MANAGED_SETTINGS_FILENAME)])).toBeNull();
  });

  it('takes the FIRST readable location and ignores later ones', () => {
    const second = mkdtempSync(join(tmpdir(), 'aka-managed-2-'));
    try {
      writeManaged({ organization: 'First' });
      writeManaged({ organization: 'Second' }, second);
      const managed = readManagedSettings([
        join(managedDir, MANAGED_SETTINGS_FILENAME),
        join(second, MANAGED_SETTINGS_FILENAME),
      ]);
      expect(managed?.organization).toBe('First');
    } finally {
      rmSync(second, { recursive: true, force: true });
    }
  });

  it('falls through a malformed first location to a valid second', () => {
    const second = mkdtempSync(join(tmpdir(), 'aka-managed-2-'));
    try {
      writeManaged({ lockedFields: ['bogus'] });
      writeManaged({ organization: 'Second' }, second);
      const managed = readManagedSettings([
        join(managedDir, MANAGED_SETTINGS_FILENAME),
        join(second, MANAGED_SETTINGS_FILENAME),
      ]);
      expect(managed?.organization).toBe('Second');
    } finally {
      rmSync(second, { recursive: true, force: true });
    }
  });
});

describe('overlayManagedSettings — what an administrator can pin', () => {
  const CLOCK = () => new Date('2026-03-04T05:06:07.000Z');

  it('is the identity when nothing is managed', () => {
    const user = settings({ historicalAccess: 'full' });
    expect(overlayManagedSettings(user, null)).toBe(user);
  });

  it('a pinned value wins over the user’s own', () => {
    const managed: ManagedSettings = {
      specVersion: 1,
      values: { historicalAccess: 'session-only' },
      lockedFields: [],
    };
    const out = overlayManagedSettings(settings({ historicalAccess: 'full' }), managed, CLOCK);
    expect(out.historicalAccess).toBe('session-only');
  });

  it('a pinned value with NO lock is a default the user may still change', () => {
    // Value and lock are separable on purpose. This case only asserts the
    // overlay; the writer half is covered under applyOnboarding below.
    const managed: ManagedSettings = {
      specVersion: 1,
      values: { vaultInlineReveal: 'off' },
      lockedFields: [],
    };
    expect(managedContextOf(managed).lockedFields).toEqual([]);
    expect(overlayManagedSettings(settings(), managed, CLOCK).vaultInlineReveal).toBe('off');
  });

  it('a lock with NO value freezes whatever the user last chose', () => {
    const managed: ManagedSettings = {
      specVersion: 1,
      values: {},
      lockedFields: ['vaultInlineReveal'],
    };
    const out = overlayManagedSettings(settings({ vaultInlineReveal: 'full' }), managed, CLOCK);
    expect(out.vaultInlineReveal).toBe('full');
    expect(managedContextOf(managed).lockedFields).toContain('vaultInlineReveal');
  });

  describe('consents — an administrator states an ANSWER, never a record', () => {
    it('materialises a grant at the CURRENT version, not one the admin chose', () => {
      const managed: ManagedSettings = {
        specVersion: 1,
        values: { vaultConsent: true, modelJudgeConsent: true },
        lockedFields: [],
      };
      const out = overlayManagedSettings(settings(), managed, CLOCK);
      expect(out.vaultConsent).toEqual({
        acknowledgedAt: '2026-03-04T05:06:07.000Z',
        version: VAULT_CONSENT_VERSION,
      });
      expect(out.modelJudgeConsent).toEqual({
        acknowledgedAt: '2026-03-04T05:06:07.000Z',
        payloadVersion: MODEL_JUDGE_PAYLOAD_VERSION,
      });
    });

    it('keeps the user’s own acknowledgedAt when their grant is already valid', () => {
      const existing = {
        acknowledgedAt: '2020-01-01T00:00:00.000Z',
        version: VAULT_CONSENT_VERSION,
      };
      const managed: ManagedSettings = {
        specVersion: 1,
        values: { vaultConsent: true },
        lockedFields: [],
      };
      const out = overlayManagedSettings(settings({ vaultConsent: existing }), managed, CLOCK);
      expect(out.vaultConsent).toEqual(existing);
    });

    it('re-stamps a STALE grant rather than carrying it forward', () => {
      // The version bump means what the grant authorizes has widened. An
      // administratively-pinned `true` re-answers at the current version; it
      // cannot resurrect consent to a payload nobody has seen.
      const stale = {
        acknowledgedAt: '2020-01-01T00:00:00.000Z',
        version: VAULT_CONSENT_VERSION + 1,
      };
      const managed: ManagedSettings = {
        specVersion: 1,
        values: { vaultConsent: true },
        lockedFields: [],
      };
      const out = overlayManagedSettings(settings({ vaultConsent: stale }), managed, CLOCK);
      expect(out.vaultConsent?.version).toBe(VAULT_CONSENT_VERSION);
      expect(out.vaultConsent?.acknowledgedAt).toBe('2026-03-04T05:06:07.000Z');
    });

    it('a pinned FALSE clears an existing grant outright', () => {
      const managed: ManagedSettings = {
        specVersion: 1,
        values: { vaultConsent: false, modelJudgeConsent: false },
        lockedFields: [],
      };
      const out = overlayManagedSettings(
        settings({
          vaultConsent: {
            acknowledgedAt: '2020-01-01T00:00:00.000Z',
            version: VAULT_CONSENT_VERSION,
          },
          modelJudgeConsent: {
            acknowledgedAt: '2020-01-01T00:00:00.000Z',
            payloadVersion: MODEL_JUDGE_PAYLOAD_VERSION,
          },
        }),
        managed,
        CLOCK,
      );
      expect(out.vaultConsent).toBeUndefined();
      expect(out.modelJudgeConsent).toBeUndefined();
    });

    it('leaves a consent the administrator said nothing about alone', () => {
      const own = { acknowledgedAt: '2020-01-01T00:00:00.000Z', version: VAULT_CONSENT_VERSION };
      const managed: ManagedSettings = { specVersion: 1, values: {}, lockedFields: ['runMode'] };
      expect(
        overlayManagedSettings(settings({ vaultConsent: own }), managed, CLOCK).vaultConsent,
      ).toEqual(own);
    });
  });

  describe('the control-plane descriptor', () => {
    it('keeps the user’s attach time when the administrator pinned the same endpoint', () => {
      const managed: ManagedSettings = {
        specVersion: 1,
        values: { runMode: 'attached', controlPlane: { endpoint: 'https://one.internal' } },
        lockedFields: ['runMode'],
      };
      const out = overlayManagedSettings(
        settings({
          runMode: 'attached',
          controlPlane: {
            endpoint: 'https://one.internal',
            attachedAt: '2024-05-05T00:00:00.000Z',
          },
        }),
        managed,
        CLOCK,
      );
      // A managed machine must not appear to re-attach on every read.
      expect(out.controlPlane?.attachedAt).toBe('2024-05-05T00:00:00.000Z');
    });

    it('stamps a fresh attach time when the administrator MOVED the endpoint', () => {
      const managed: ManagedSettings = {
        specVersion: 1,
        values: { controlPlane: { endpoint: 'https://two.internal' } },
        lockedFields: [],
      };
      const out = overlayManagedSettings(
        settings({
          controlPlane: {
            endpoint: 'https://one.internal',
            attachedAt: '2024-05-05T00:00:00.000Z',
          },
        }),
        managed,
        CLOCK,
      );
      expect(out.controlPlane?.endpoint).toBe('https://two.internal');
      expect(out.controlPlane?.attachedAt).toBe('2026-03-04T05:06:07.000Z');
    });
  });
});

describe('the two helpers every surface words a lock through', () => {
  const ctx = (over: Partial<ManagedContext> = {}): ManagedContext => ({
    present: true,
    lockedFields: ['runMode'],
    ...over,
  });

  it('isFieldManaged is false for every key on an unmanaged machine', () => {
    // `present` gates it, not the list: a context that somehow carried locked
    // fields while absent must still lock nothing.
    const absent: ManagedContext = { present: false, lockedFields: ['runMode'] };
    expect(isFieldManaged(absent, 'runMode')).toBe(false);
  });

  it('isFieldManaged names only the frozen keys', () => {
    expect(isFieldManaged(ctx(), 'runMode')).toBe(true);
    expect(isFieldManaged(ctx(), 'vaultConsent')).toBe(false);
  });

  it('managedByLabel names the organization when one is given', () => {
    expect(managedByLabel(ctx({ organization: 'Acme' }))).toContain('Acme');
  });

  it('managedByLabel still says WHO decided when no organization is given', () => {
    // The fallback has to remain a sentence about an administrator, not an
    // empty name — the whole point of the label is that a locked control reads
    // as a decision rather than a bug.
    const label = managedByLabel(ctx());
    expect(label).toMatch(/your organization/i);
    expect(label).not.toContain('undefined');
  });
});

describe('lockedAmong — which of a write’s keys an administrator froze', () => {
  it('is empty on an unmanaged machine, whatever is asked for', () => {
    expect(lockedAmong(managedContextOf(null), ['runMode', 'vaultConsent'])).toEqual([]);
  });

  it('returns only the intersection', () => {
    const ctx = managedContextOf({
      specVersion: 1,
      values: {},
      lockedFields: ['runMode', 'vaultConsent'],
    });
    expect(lockedAmong(ctx, ['vaultConsent', 'historicalAccess'])).toEqual(['vaultConsent']);
  });
});

describe('readEffectiveSettings — what is actually in force', () => {
  it('reports an unmanaged machine as unmanaged', () => {
    const { managed } = readEffectiveSettings(base, null);
    expect(managed.present).toBe(false);
    expect(managed.lockedFields).toEqual([]);
  });

  it('applies the overlay and reports what is locked', () => {
    applyOnboarding({ historicalAccess: 'full' }, base, null);
    const { settings: effective, managed } = readEffectiveSettings(base, {
      specVersion: 1,
      organization: 'Acme',
      values: { historicalAccess: 'session-only' },
      lockedFields: ['historicalAccess'],
    });
    expect(effective.historicalAccess).toBe('session-only');
    expect(managed.present).toBe(true);
    expect(managed.organization).toBe('Acme');
    expect(managed.lockedFields).toEqual(['historicalAccess']);
  });
});

describe('the overlay is read LIVE, never memoized', () => {
  // tokenize.ts's consent gate calls readWorkspaceSettings on every tokenize
  // precisely so a revocation applies to the very next call rather than the
  // next process. A per-process cache of the managed half breaks that for an
  // ADMINISTRATIVE revocation — the one an operator can least work around,
  // since they cannot restart a user's dashboard.
  it('sees an administrator appear between two reads in one process', () => {
    applyOnboarding({ historicalAccess: 'full' }, base, null);
    expect(readWorkspaceSettings(base).historicalAccess).toBe('full');

    writeManaged({
      values: { historicalAccess: 'session-only' },
      lockedFields: ['historicalAccess'],
    });
    // Same process, same module instance, no reset call available or needed.
    expect(
      readEffectiveSettings(base, readManagedSettings([managedFile()])).settings.historicalAccess,
    ).toBe('session-only');
  });

  it('sees an administrator DISAPPEAR between two reads in one process', () => {
    // The direction that matters most: a lock lifted must stop applying, or a
    // user stays governed by a file their administrator already removed.
    applyOnboarding({ historicalAccess: 'full' }, base, null);
    const managed: ManagedSettings = {
      specVersion: 1,
      values: { historicalAccess: 'session-only' },
      lockedFields: [],
    };
    expect(readEffectiveSettings(base, managed).settings.historicalAccess).toBe('session-only');
    expect(readEffectiveSettings(base, null).settings.historicalAccess).toBe('full');
  });
});

describe('applyOnboarding — refusing an administratively locked write', () => {
  it('writes normally when nothing is locked', () => {
    const out = applyOnboarding({ historicalAccess: 'full' }, base, null);
    expect(out.historicalAccess).toBe('full');
  });

  it('THROWS rather than dropping the locked key and writing the rest', () => {
    // Silently discarding half a save is the shape this writer exists to
    // prevent: the user is told it saved and the answer they cared about is
    // gone. Both callers already surface a throw.
    applyOnboarding({ historicalAccess: 'session-only', vaultInlineReveal: 'masked' }, base, null);
    const managed: ManagedSettings = {
      specVersion: 1,
      values: {},
      lockedFields: ['historicalAccess'],
    };
    expect(() =>
      applyOnboarding({ historicalAccess: 'full', vaultInlineReveal: 'off' }, base, managed),
    ).toThrow(ManagedFieldError);

    // The UNLOCKED sibling in the same write did not land either — the refusal
    // is decided before the merge, so nothing partial reaches disk.
    const after = readEffectiveSettings(base, null).settings;
    expect(after.historicalAccess).toBe('session-only');
    expect(after.vaultInlineReveal).toBe('masked');
  });

  it('names the refused fields, and only those', () => {
    const managed: ManagedSettings = {
      specVersion: 1,
      values: {},
      lockedFields: ['historicalAccess', 'runMode'],
    };
    let caught: unknown;
    try {
      applyOnboarding({ historicalAccess: 'full', vaultInlineReveal: 'off' }, base, managed);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ManagedFieldError);
    expect((caught as ManagedFieldError).fields).toEqual(['historicalAccess']);
  });

  it('allows a write that touches no locked key', () => {
    const managed: ManagedSettings = { specVersion: 1, values: {}, lockedFields: ['runMode'] };
    expect(() => applyOnboarding({ historicalAccess: 'full' }, base, managed)).not.toThrow();
    expect(readEffectiveSettings(base, null).settings.historicalAccess).toBe('full');
  });

  it('does NOT refuse when the form echoes an administrator PINNED value back', () => {
    // The case the dashboard actually produces on a managed machine. The page
    // renders the EFFECTIVE settings, so a locked-and-pinned field comes back
    // in the payload carrying the ADMINISTRATOR's value — which differs from
    // what is in the user's own file. Compared against the raw file that reads
    // as a change and refuses, so every save on such a machine fails, including
    // saves of entirely unlocked fields.
    applyOnboarding({ historicalAccess: 'full', vaultInlineReveal: 'masked' }, base, null);
    const managed: ManagedSettings = {
      specVersion: 1,
      values: { historicalAccess: 'session-only' },
      lockedFields: ['historicalAccess'],
    };
    // What the page would show, and therefore post back.
    expect(readEffectiveSettings(base, managed).settings.historicalAccess).toBe('session-only');

    expect(() =>
      applyOnboarding(
        { historicalAccess: 'session-only', vaultInlineReveal: 'off' },
        base,
        managed,
      ),
    ).not.toThrow();
    expect(readEffectiveSettings(base, managed).settings.vaultInlineReveal).toBe('off');
  });

  it('does not PERSIST an administrator pin into the user own file', () => {
    // The other half, and why the echo is dropped rather than merged: a pin
    // written into settings.json would outlive the managed file, so removing
    // the lock would leave the administrator's answer behind as though the user
    // had chosen it.
    applyOnboarding({ historicalAccess: 'full' }, base, null);
    const managed: ManagedSettings = {
      specVersion: 1,
      values: { historicalAccess: 'session-only' },
      lockedFields: ['historicalAccess'],
    };
    applyOnboarding({ historicalAccess: 'session-only', vaultInlineReveal: 'off' }, base, managed);

    // With the administrator gone, the user's own choice is still theirs.
    expect(readEffectiveSettings(base, null).settings.historicalAccess).toBe('full');
  });

  it('still refuses when the user tries to change a locked field away from the pin', () => {
    // The positive control: relaxing the echo case must not relax the lock.
    applyOnboarding({ historicalAccess: 'full' }, base, null);
    const managed: ManagedSettings = {
      specVersion: 1,
      values: { historicalAccess: 'session-only' },
      lockedFields: ['historicalAccess'],
    };
    expect(() => applyOnboarding({ historicalAccess: 'full' }, base, managed)).toThrow(
      ManagedFieldError,
    );
  });

  it('does not persist an UNLOCKED pin the form echoed back', () => {
    // The other supported configuration: a pinned value with NO lock, which
    // this layer calls "a DEFAULT the user may then change". The stripper only
    // looked at the lock list, so the administrator's answer landed in the
    // user's own file the first time the form echoed it — and then outlived the
    // managed file, reading as the user's own choice.
    applyOnboarding({ vaultInlineReveal: 'full', historicalAccess: 'full' }, base, null);
    const managed: ManagedSettings = {
      specVersion: 1,
      values: { historicalAccess: 'session-only' },
      lockedFields: [],
    };
    // The page renders the pin, so the client posts it back alongside a real edit.
    applyOnboarding(
      { historicalAccess: 'session-only', vaultInlineReveal: 'masked' },
      base,
      managed,
    );

    // The real edit landed…
    expect(readEffectiveSettings(base, null).settings.vaultInlineReveal).toBe('masked');
    // …and with the administrator gone, the user's own answer is still theirs.
    expect(readEffectiveSettings(base, null).settings.historicalAccess).toBe('full');
  });

  it('does not turn an UNLOCKED vaultConsent pin into a recorded grant', () => {
    // The variant that matters most: the echoed pin becomes a real custody
    // grant, with an acknowledgedAt the user never gave, that survives the
    // managed file being removed.
    applyOnboarding({ historicalAccess: 'full' }, base, null);
    const managed: ManagedSettings = {
      specVersion: 1,
      values: { vaultConsent: true },
      lockedFields: [],
    };
    // What the page shows, hence what the client posts back.
    expect(readEffectiveSettings(base, managed).settings.vaultConsent).toBeDefined();
    applyOnboarding(
      (current) => ({
        // Exactly what saveSettings does: an invalid current grant mints a real one.
        vaultConsent: current.vaultConsent ?? {
          acknowledgedAt: new Date().toISOString(),
          version: VAULT_CONSENT_VERSION,
        },
        vaultInlineReveal: 'off',
      }),
      base,
      managed,
    );

    expect(readEffectiveSettings(base, null).settings.vaultInlineReveal).toBe('off');
    // No grant on file once the administrator's is gone.
    expect(readEffectiveSettings(base, null).settings.vaultConsent).toBeUndefined();
  });

  it('still writes a pinned key the user actually CHANGED', () => {
    // The positive control: stripping a pin must not swallow a real edit. An
    // unlocked pin is a default, so changing it is the user's to make.
    applyOnboarding({ historicalAccess: 'full' }, base, null);
    const managed: ManagedSettings = {
      specVersion: 1,
      values: { vaultInlineReveal: 'masked' },
      lockedFields: [],
    };
    applyOnboarding({ vaultInlineReveal: 'off' }, base, managed);
    expect(readEffectiveSettings(base, null).settings.vaultInlineReveal).toBe('off');
  });

  it('refuses a DETACH when the connection is locked', () => {
    // The ask this exists for: a machine an administrator attached is not one
    // the user may leave.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: 'https://acme.internal', attachedAt: '2026-01-01T00:00:00.000Z' },
      },
      base,
      null,
    );
    const managed: ManagedSettings = { specVersion: 1, values: {}, lockedFields: ['runMode'] };
    expect(() =>
      applyOnboarding({ runMode: 'standalone', controlPlane: undefined }, base, managed),
    ).toThrow(ManagedFieldError);
    expect(readEffectiveSettings(base, null).settings.runMode).toBe('attached');
  });

  it('refuses a LABEL-only change to a locked connection', () => {
    // The two halves of the lock have to agree about what a change is:
    // withoutLockedKeys strips `controlPlane` wholesale when runMode is locked,
    // so a field the refusal ignores is one a caller changes without being
    // refused and then has silently discarded — the write reporting success
    // while the label it was asked to set went nowhere.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: {
          endpoint: 'https://acme.internal',
          label: 'Old Name',
          attachedAt: '2026-01-01T00:00:00.000Z',
        },
      },
      base,
      null,
    );
    const managed: ManagedSettings = { specVersion: 1, values: {}, lockedFields: ['runMode'] };
    expect(() =>
      applyOnboarding(
        {
          runMode: 'attached',
          controlPlane: {
            endpoint: 'https://acme.internal',
            label: 'New Name',
            attachedAt: '2026-02-02T00:00:00.000Z',
          },
        },
        base,
        managed,
      ),
    ).toThrow(ManagedFieldError);
    expect(readEffectiveSettings(base, null).settings.controlPlane?.label).toBe('Old Name');
  });

  it('does not refuse a re-attach that changes only the server-stamped time', () => {
    // attachedAt is stamped on every attach, so counting it as a change would
    // refuse an otherwise-identical re-attach on a locked machine.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: {
          endpoint: 'https://acme.internal',
          label: 'Same',
          attachedAt: '2026-01-01T00:00:00.000Z',
        },
      },
      base,
      null,
    );
    const managed: ManagedSettings = { specVersion: 1, values: {}, lockedFields: ['runMode'] };
    expect(() =>
      applyOnboarding(
        {
          runMode: 'attached',
          controlPlane: {
            endpoint: 'https://acme.internal',
            label: 'Same',
            attachedAt: '2026-09-09T00:00:00.000Z',
          },
        },
        base,
        managed,
      ),
    ).not.toThrow();
  });

  it('treats a controlPlane-only write as touching the locked runMode', () => {
    // Clearing the descriptor detaches just as surely as clearing the mode
    // (isAttached needs both), so the lock has to cover the pair. The machine
    // has to be genuinely attached first — clearing a descriptor that is
    // already absent changes nothing, and refusing THAT would be the
    // presence-not-value bug this comparison exists to avoid.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: 'https://acme.internal', attachedAt: '2026-01-01T00:00:00.000Z' },
      },
      base,
      null,
    );
    const managed: ManagedSettings = { specVersion: 1, values: {}, lockedFields: ['runMode'] };
    expect(() => applyOnboarding({ controlPlane: undefined }, base, managed)).toThrow(
      ManagedFieldError,
    );
  });

  it('does NOT refuse a save that re-sends a locked field UNCHANGED', () => {
    // The dashboard posts every field it renders on every save, touched or not.
    // A presence-based check would refuse every save as soon as ANY field was
    // locked, collapsing per-field locks into an all-or-nothing one while the
    // UI went on showing the other rows as editable.
    applyOnboarding({ historicalAccess: 'full', vaultInlineReveal: 'masked' }, base, null);
    const managed: ManagedSettings = {
      specVersion: 1,
      values: {},
      lockedFields: ['historicalAccess'],
    };
    expect(() =>
      applyOnboarding(
        // historicalAccess is LOCKED but unchanged; vaultInlineReveal is the edit.
        { historicalAccess: 'full', vaultInlineReveal: 'off' },
        base,
        managed,
      ),
    ).not.toThrow();
    expect(readEffectiveSettings(base, null).settings.vaultInlineReveal).toBe('off');
  });

  it('does not refuse a re-sent consent grant that keeps the same ANSWER', () => {
    // A grant re-sent with a fresh acknowledgedAt is the same answer. Comparing
    // the RECORD rather than the answer would refuse an unrelated save on any
    // machine whose vault consent is locked and granted.
    applyOnboarding(
      {
        vaultConsent: {
          acknowledgedAt: '2026-01-01T00:00:00.000Z',
          version: VAULT_CONSENT_VERSION,
        },
      },
      base,
      null,
    );
    const managed: ManagedSettings = { specVersion: 1, values: {}, lockedFields: ['vaultConsent'] };
    expect(() =>
      applyOnboarding(
        {
          vaultConsent: {
            acknowledgedAt: '2026-09-09T00:00:00.000Z',
            version: VAULT_CONSENT_VERSION,
          },
          vaultInlineReveal: 'off',
        },
        base,
        managed,
      ),
    ).not.toThrow();
  });

  it('DOES refuse a locked consent whose answer actually flips', () => {
    // The positive control for the two cases above: relaxing the comparison
    // must not relax the lock itself.
    applyOnboarding(
      {
        vaultConsent: {
          acknowledgedAt: '2026-01-01T00:00:00.000Z',
          version: VAULT_CONSENT_VERSION,
        },
      },
      base,
      null,
    );
    const managed: ManagedSettings = { specVersion: 1, values: {}, lockedFields: ['vaultConsent'] };
    expect(() => applyOnboarding({ vaultConsent: undefined }, base, managed)).toThrow(
      ManagedFieldError,
    );
  });
});

// Every lockable key, driven through all four hand-written per-key lists.
//
// `overlayManagedSettings` (managed-settings.ts) and `lockableKeysTouched`,
// `pinnedKeys` and `withoutManagedKeys` (settings.ts) each spell their keys out
// by hand. Nothing derived them from the schema, so a key added to
// `ManagedSettingKey` and `ManagedSettingsValues` and then forgotten in any one
// of the four left the whole suite GREEN while that key was silently
// unmanageable — an administrator's pin ignored, or a lock that refuses
// nothing.
//
// The table below closes that, and it is deliberately a `Record<ManagedSettingKey, …>`:
// a member added to the enum fails to COMPILE here until someone writes down
// what pinning it should do, and the three cases then fail at RUNTIME if any of
// the four lists does not handle it. Structural exhaustiveness alone would not
// do — a key can be present in every list and still be handled wrongly — so
// each case asserts behaviour a user would notice.
interface KeySample {
  /** What an administrator writes under `values`. */
  readonly pin: Partial<ManagedSettings['values']>;
  /** A user answer that DIFFERS from the pin, so a lock has something to refuse. */
  readonly userAnswer: Partial<WorkspaceSettings>;
  /** A user answer equal to the pinned value — the form echoing the pin back. */
  readonly echoAnswer: Partial<WorkspaceSettings>;
  /** The observable this key controls. */
  readonly read: (s: WorkspaceSettings) => unknown;
  readonly underPin: unknown;
  readonly underUser: unknown;
}

const grant = () => ({ acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION });
const judgeGrant = () => ({
  acknowledgedAt: new Date().toISOString(),
  payloadVersion: MODEL_JUDGE_PAYLOAD_VERSION,
});

const KEY_SAMPLES = {
  runMode: {
    pin: { runMode: 'attached', controlPlane: { endpoint: 'https://cp.example' } },
    userAnswer: { runMode: 'standalone' },
    echoAnswer: { runMode: 'attached' },
    read: (s) => s.runMode,
    underPin: 'attached',
    underUser: 'standalone',
  },
  historicalAccess: {
    pin: { historicalAccess: 'session-only' },
    userAnswer: { historicalAccess: 'full' },
    echoAnswer: { historicalAccess: 'session-only' },
    read: (s) => s.historicalAccess,
    underPin: 'session-only',
    underUser: 'full',
  },
  vaultConsent: {
    pin: { vaultConsent: true },
    userAnswer: { vaultConsent: undefined },
    echoAnswer: { vaultConsent: grant() },
    read: (s) => s.vaultConsent !== undefined,
    underPin: true,
    underUser: false,
  },
  vaultKeyCustody: {
    pin: { vaultKeyCustody: 'keychain' },
    userAnswer: { vaultKeyCustody: 'file' },
    echoAnswer: { vaultKeyCustody: 'keychain' },
    read: (s) => s.vaultKeyCustody,
    underPin: 'keychain',
    underUser: 'file',
  },
  vaultInlineReveal: {
    pin: { vaultInlineReveal: 'off' },
    userAnswer: { vaultInlineReveal: 'full' },
    echoAnswer: { vaultInlineReveal: 'off' },
    read: (s) => s.vaultInlineReveal,
    underPin: 'off',
    underUser: 'full',
  },
  modelJudgeConsent: {
    pin: { modelJudgeConsent: true },
    userAnswer: { modelJudgeConsent: undefined },
    echoAnswer: { modelJudgeConsent: judgeGrant() },
    read: (s) => s.modelJudgeConsent !== undefined,
    underPin: true,
    underUser: false,
  },
  redactFallback: {
    pin: { redactFallback: 'block' },
    userAnswer: { redactFallback: 'monitor' },
    echoAnswer: { redactFallback: 'block' },
    read: (s) => s.redactFallback,
    underPin: 'block',
    underUser: 'monitor',
  },
  dataSharesInPlace: {
    pin: { dataSharesInPlace: true },
    userAnswer: { dataSharesInPlace: false },
    echoAnswer: { dataSharesInPlace: true },
    read: (s) => s.dataSharesInPlace,
    underPin: true,
    underUser: false,
  },
} satisfies Record<ManagedSettingKey, KeySample>;

describe('every lockable key is handled by all four per-key lists', () => {
  const entries = Object.entries(KEY_SAMPLES) as [ManagedSettingKey, KeySample][];

  it('drives every member of ManagedSettingKey', () => {
    // The table is compile-checked exhaustive; this says so at runtime too, so
    // a reader of a failure below knows the sweep was complete.
    expect(entries.map(([k]) => k).sort()).toEqual([...ManagedSettingKey.options].sort());
  });

  it.each(entries)('%s: an administrator pin reaches the effective settings', (_key, sample) => {
    // Covers overlayManagedSettings. A key missing from it reads back as the
    // product default and the administrator's answer is silently ignored.
    applyOnboarding(sample.userAnswer, base, null);
    const managed: ManagedSettings = { specVersion: 1, values: sample.pin, lockedFields: [] };
    expect(sample.read(readEffectiveSettings(base, managed).settings)).toEqual(sample.underPin);
  });

  it.each(entries)('%s: a lock refuses a change away from the pin, naming it', (key, sample) => {
    // Covers lockableKeysTouched. A key missing from it is a lock that refuses
    // nothing — the write succeeds and the administrator's decision is lost.
    applyOnboarding(sample.userAnswer, base, null);
    const managed: ManagedSettings = { specVersion: 1, values: sample.pin, lockedFields: [key] };
    let caught: unknown;
    try {
      applyOnboarding(sample.userAnswer, base, managed);
    } catch (err) {
      caught = err;
    }
    expect(caught, `${key}: locking it refused nothing`).toBeInstanceOf(ManagedFieldError);
    expect((caught as ManagedFieldError).fields).toContain(key);
  });

  it.each(entries)(
    '%s: an unlocked pin is not persisted into the user own file',
    (_key, sample) => {
      // Covers pinnedKeys and withoutManagedKeys together. A key missing from
      // either lets the administrator's answer land in settings.json, where it
      // outlives the managed file and reads as the user's own choice.
      applyOnboarding(sample.userAnswer, base, null);
      const managed: ManagedSettings = { specVersion: 1, values: sample.pin, lockedFields: [] };
      // The form renders the effective (pinned) value and posts it back.
      applyOnboarding(sample.echoAnswer, base, managed);
      expect(sample.read(readWorkspaceSettings(base))).toEqual(sample.underUser);
    },
  );
});
