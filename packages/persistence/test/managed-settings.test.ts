import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { ManagedSettings, WorkspaceSettings } from '@akasecurity/schema';
import {
  defaultWorkspaceSettings,
  MANAGED_SETTINGS_FILENAME,
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
import { applyOnboarding, ManagedFieldError, readEffectiveSettings } from '../src/settings.ts';

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
