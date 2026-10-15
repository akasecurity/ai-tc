import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { ManagedSettings, SimpleDetectionPolicy } from '@akasecurity/schema';
import {
  canSweepSyncLane,
  isAttached,
  isAttachmentScopeValid,
  parseAttachmentScope,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyOnboarding, readEffectiveSettings, readWorkspaceSettings } from '../src/settings.ts';

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-settings-'));
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

function writeSettings(contents: unknown): void {
  const dir = join(base, 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'settings.json'), JSON.stringify(contents));
}

describe('readWorkspaceSettings', () => {
  it('returns unonboarded defaults when settings.json is absent', () => {
    const settings = readWorkspaceSettings(base);
    expect(settings.runMode).toBe('standalone');
    expect(settings.policy).toBe('redact');
    expect(settings.onboardedAt).toBeUndefined();
  });

  it('reads saved answers', () => {
    writeSettings({
      specVersion: 1,
      runMode: 'standalone',
      policy: 'warn',
      onboardedAt: '2026-06-19T00:00:00.000Z',
    });
    const settings = readWorkspaceSettings(base);
    expect(settings.runMode).toBe('standalone');
    expect(settings.policy).toBe('warn');
    expect(settings.onboardedAt).toBe('2026-06-19T00:00:00.000Z');
  });

  it('reads back both run modes, keeping the rest of the file', () => {
    writeSettings({ specVersion: 1, runMode: 'attached', policy: 'warn' });
    const settings = readWorkspaceSettings(base);
    expect(settings.runMode).toBe('attached');
    expect(settings.policy).toBe('warn'); // the rest of the file is untouched
  });

  it('an unknown runMode still falls back to unonboarded defaults', () => {
    // The enum was widened, not opened: a typo must not load as a real mode.
    // The whole object fails to parse, which is the documented fail-open — the
    // point of this case is that it is not silently coerced to 'attached'.
    writeSettings({ specVersion: 1, runMode: 'atached' });
    expect(readWorkspaceSettings(base).runMode).toBe('standalone');
  });

  it('default-fills missing keys so an older partial settings.json still parses', () => {
    writeSettings({ policy: 'warn' });
    const settings = readWorkspaceSettings(base);
    expect(settings.policy).toBe('warn');
    expect(settings.runMode).toBe('standalone'); // defaulted
    expect(settings.historicalAccess).toBe('session-only'); // defaulted, never an assumed grant
    expect(settings.onboardedAt).toBeUndefined();
  });

  it('falls back to defaults on a corrupt settings.json (fail-open)', () => {
    const dir = join(base, 'settings');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'settings.json'), '{ not json');
    const settings = readWorkspaceSettings(base);
    expect(settings.runMode).toBe('standalone');
    expect(settings.onboardedAt).toBeUndefined();
  });

  it('is a pure reader — reading does not alter settings.json mode', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // The self-heal deliberately lives in the write/init/loadConfig paths, not
    // here: a documented fail-open reader (also called from a web-ui page render)
    // must not chmod on every read. This pins that contract so nobody re-adds it.
    writeSettings({ specVersion: 1, runMode: 'standalone', policy: 'warn' });
    const file = join(base, 'settings', 'settings.json');
    chmodSync(file, 0o644);

    const settings = readWorkspaceSettings(base);

    expect(settings.policy).toBe('warn'); // reads correctly
    expect(statSync(file).mode & 0o777).toBe(0o644); // and leaves the mode untouched
  });
});

describe('applyOnboarding', () => {
  it('persists answers, stamps onboardedAt, and writes the file owner-only', () => {
    const saved = applyOnboarding({ policy: 'warn' }, base);
    expect(saved.policy).toBe('warn');
    expect(saved.onboardedAt).toBeDefined();

    const settings = readWorkspaceSettings(base);
    expect(settings.policy).toBe('warn');
    expect(settings.onboardedAt).toBe(saved.onboardedAt);
    if (process.platform !== 'win32') {
      const file = join(base, 'settings', 'settings.json');
      expect(statSync(file).mode & 0o777).toBe(0o600);
    }
  });

  it('writes settings.json 0600 even over a leftover loose .tmp', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const dir = join(base, 'settings');
    mkdirSync(dir, { recursive: true });
    // A crash between the tmp write and the rename can leave a stale tmp behind.
    // writeFileSync's `mode` option is honored only on creation, so the owner-only
    // writer clears that tmp first (and re-tightens after the rename) rather than
    // carrying its loose mode onto settings.json.
    //
    // The tmp name has to carry THIS process's pid, because that is the path the
    // writer builds and therefore the only one it can collide with. A plain
    // `settings.json.tmp` is a file the writer never touches, so the fixture is
    // inert and the case holds on the create mode alone — which is what it did
    // until the writer's tmp became per-process.
    const tmp = join(dir, `settings.json.${String(process.pid)}.tmp`);
    writeFileSync(tmp, 'stale');
    chmodSync(tmp, 0o666);

    applyOnboarding({ policy: 'warn' }, base);

    // The writer consumed the planted tmp — it clears that path, writes it
    // exclusively, and removes it again. A tmp still sitting there is one the
    // writer never touched, i.e. the name above has drifted from the one it
    // builds and the fixture is back to being inert. Assert it before the mode,
    // because a mode of 0600 holds on the create mode alone either way.
    expect(existsSync(tmp)).toBe(false);

    const file = join(dir, 'settings.json');
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('round-trips the Data Shares kill-switch through the settings file', () => {
    // Defaults on, so disabling it must survive the write/read cycle rather than
    // being re-defaulted back to true on the next read.
    expect(readWorkspaceSettings(base).dataSharesInPlace).toBe(true);

    const saved = applyOnboarding({ dataSharesInPlace: false }, base);
    expect(saved.dataSharesInPlace).toBe(false);
    expect(readWorkspaceSettings(base).dataSharesInPlace).toBe(false);

    expect(applyOnboarding({ dataSharesInPlace: true }, base).dataSharesInPlace).toBe(true);
    expect(readWorkspaceSettings(base).dataSharesInPlace).toBe(true);
  });

  it('merges additive answers across calls and keeps the original onboardedAt', () => {
    const first = applyOnboarding({ policy: 'warn' }, base);
    const second = applyOnboarding({ historicalAccess: 'full' }, base);
    expect(second.policy).toBe('warn'); // preserved from the first call
    expect(second.historicalAccess).toBe('full'); // newly applied
    expect(second.onboardedAt).toBe(first.onboardedAt); // stable across edits
  });

  it('leaves no lock file behind', () => {
    applyOnboarding({ policy: 'warn' }, base);
    // The write lock is a sibling of settings.json. One left behind costs every
    // later writer its full stale wait before it can proceed.
    expect(readdirSync(join(base, 'settings'))).toEqual(['settings.json']);
  });
});

describe('applyOnboarding (derived answers)', () => {
  it('hands the updater the settings already on disk', () => {
    applyOnboarding({ policy: 'warn' }, base);

    let seen: SimpleDetectionPolicy | undefined;
    applyOnboarding((current) => {
      seen = current.policy;
      return { historicalAccess: 'full' };
    }, base);

    expect(seen).toBe('warn');
    expect(readWorkspaceSettings(base).historicalAccess).toBe('full');
    expect(readWorkspaceSettings(base).policy).toBe('warn');
  });

  it('merges what the updater returns, exactly as a plain answer object would', () => {
    const saved = applyOnboarding(() => ({ policy: 'warn' }), base);
    expect(saved.policy).toBe('warn');
    expect(saved.onboardedAt).toBeDefined();
    expect(readWorkspaceSettings(base).policy).toBe('warn');
  });

  it('lets an updater carry a value forward from the current settings', () => {
    // The dashboard's shape: a consent grant that survives an unrelated edit is
    // read on the far side of the lock, so it is the grant still on file rather
    // than one a concurrent revoke has since cleared.
    const granted = { acknowledgedAt: '2026-01-01T00:00:00.000Z', version: 1 };
    applyOnboarding({ vaultConsent: granted }, base);

    applyOnboarding((current) => ({ policy: 'warn', vaultConsent: current.vaultConsent }), base);

    expect(readWorkspaceSettings(base).vaultConsent).toEqual(granted);
    expect(readWorkspaceSettings(base).policy).toBe('warn');
  });

  it('drops a field the updater returns as undefined', () => {
    applyOnboarding(
      { modelJudgeConsent: { acknowledgedAt: '2026-01-01T00:00:00.000Z', payloadVersion: 1 } },
      base,
    );
    applyOnboarding(() => ({ modelJudgeConsent: undefined }), base);
    expect(readWorkspaceSettings(base).modelJudgeConsent).toBeUndefined();
  });

  it('does not write when the updater throws', () => {
    applyOnboarding({ policy: 'warn' }, base);
    expect(() =>
      applyOnboarding(() => {
        throw new Error('derivation failed');
      }, base),
    ).toThrow('derivation failed');
    expect(readWorkspaceSettings(base).policy).toBe('warn');
    // And the lock is released, so the next writer is not left waiting it out.
    expect(applyOnboarding({ historicalAccess: 'full' }, base).historicalAccess).toBe('full');
  });
});

// What an attach leaves in the user's own file when an administrator pinned the
// connection it names. The pin says which deployment and in which mode; it cannot
// say when this machine joined, or what the user called it. Every case injects
// its overlay, and `readEffectiveSettings(base, null)` reads the user's own file
// as it would stand with the administrator gone.
describe('applyOnboarding (an attach under a pinned connection)', () => {
  const PINNED = 'https://pinned.internal';
  const EARLIER = 'https://earlier.internal';
  const ENROLLED_AT = '2026-02-02T00:00:00.000Z';
  // The shape a fleet ships: the mode and the deployment pinned, nothing locked.
  const fleet: ManagedSettings = {
    specVersion: 1,
    values: { runMode: 'attached', controlPlane: { endpoint: PINNED } },
    lockedFields: [],
  };
  // A pin that moved the machine and left the mode the user's own.
  const moved: ManagedSettings = {
    specVersion: 1,
    values: { controlPlane: { endpoint: PINNED } },
    lockedFields: [],
  };

  it('keeps the time an enrolment stamps where its connection echoes the pin', () => {
    // Endpoint and mode both equal what the pin supplies, so the only thing
    // this write says that the pin does not is WHEN. Dropped, the machine would
    // read as attached "just now" on every read.
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: PINNED, attachedAt: ENROLLED_AT } },
      base,
      fleet,
    );
    expect(readEffectiveSettings(base, fleet).settings.controlPlane?.attachedAt).toBe(ENROLLED_AT);
  });

  it('replaces an earlier deployment’s attach time with the enrolment’s own', () => {
    // The history drain freezes a new deployment's first boundary at this
    // time. Left at the earlier attachment's, activity recorded between that
    // attach and this enrolment would reach neither the drain nor the live path.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: EARLIER, attachedAt: '2026-01-01T00:00:00.000Z' },
      },
      base,
      null,
    );
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: PINNED, attachedAt: ENROLLED_AT } },
      base,
      moved,
    );
    expect(readEffectiveSettings(base, moved).settings.controlPlane?.attachedAt).toBe(ENROLLED_AT);
  });

  it('does not carry the pinned mode it echoes into the user’s own file', () => {
    // The mode is what makes a machine forward, and the pin already supplies
    // it. Written into the user's file it would keep the machine attached after
    // the managed file was removed, reading as the user's own choice.
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: PINNED, attachedAt: ENROLLED_AT } },
      base,
      fleet,
    );
    const own = readEffectiveSettings(base, null).settings;
    expect(own.runMode).toBe('standalone');
    expect(isAttached(own)).toBe(false);
  });

  it('does not persist a pinned descriptor echoed back with the time already on file', () => {
    // A surface that posts back what every read shows carries the attach time
    // the user's file already holds. That is an echo, not an enrolment, and it
    // must not overwrite the user's own record with the pinned deployment.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: EARLIER, attachedAt: '2026-01-01T00:00:00.000Z' },
      },
      base,
      null,
    );
    const shown = readEffectiveSettings(base, moved).settings;
    expect(shown.controlPlane?.endpoint).toBe(PINNED);

    applyOnboarding({ runMode: shown.runMode, controlPlane: shown.controlPlane }, base, moved);

    expect(readEffectiveSettings(base, null).settings.controlPlane?.endpoint).toBe(EARLIER);
  });

  it('keeps a name given under a pinned mode without carrying the mode', () => {
    // The mode and the descriptor are judged apart. A rename changes the
    // descriptor alone, so the mode it echoes is dropped like any other echo.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: PINNED, label: 'MyBox', attachedAt: ENROLLED_AT },
      },
      base,
      fleet,
    );
    const own = readEffectiveSettings(base, null).settings;
    expect(own.controlPlane?.label).toBe('MyBox');
    expect(own.runMode).toBe('standalone');
  });

  it('keeps a re-attach’s own time under a lock, which freezes the deployment but not when', () => {
    // A lock refuses a change of deployment or name, and a re-attach that
    // changes neither is let through. What it stamps is this machine's record,
    // exactly as an unmanaged re-attach's is.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: PINNED, label: 'Same', attachedAt: '2026-01-01T00:00:00.000Z' },
      },
      base,
      null,
    );
    const locked: ManagedSettings = { specVersion: 1, values: {}, lockedFields: ['runMode'] };
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: PINNED, label: 'Same', attachedAt: ENROLLED_AT },
      },
      base,
      locked,
    );
    expect(readEffectiveSettings(base, locked).settings.controlPlane?.attachedAt).toBe(ENROLLED_AT);
  });

  it('clears the kept record on a detach', () => {
    // Where the mode is the user's to change, a detach takes the enrolment's
    // record with it, so nothing names the deployment once the pin is gone.
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: PINNED, attachedAt: ENROLLED_AT } },
      base,
      moved,
    );
    applyOnboarding({ runMode: 'standalone', controlPlane: undefined }, base, moved);
    expect(readEffectiveSettings(base, null).settings.controlPlane).toBeUndefined();
  });

  it('holds body expiry off the sync lane while the kept record stands, until a detach', () => {
    // An enrolment with no history-sync grant, and then the administrator gone:
    // the machine reads standalone, and the record it kept is still enough to
    // keep the sync lane's bodies, as a grant would. A detach releases them.
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: PINNED, attachedAt: ENROLLED_AT } },
      base,
      fleet,
    );
    const own = readEffectiveSettings(base, null).settings;
    expect(isAttached(own)).toBe(false);
    expect(own.historySyncConsent).toBeUndefined();
    expect(canSweepSyncLane(own)).toBe(false);

    applyOnboarding(
      { runMode: 'standalone', controlPlane: undefined, historySyncConsent: undefined },
      base,
      null,
    );
    expect(canSweepSyncLane(readEffectiveSettings(base, null).settings)).toBe(true);
  });
});

describe('a garbled attachmentScope', () => {
  // The scope record sits in the same file as the attachment it scopes, and the
  // reader parses that file whole or falls back to unonboarded defaults. So one
  // bad enrollment must cost that enrollment and nothing else: a record that
  // took the file down with it would read as a machine that was never attached
  // or onboarded, and the next save would write those defaults over it.
  const ENDPOINT = 'https://plane.example.test';
  const AT = '2026-09-01T00:00:00.000Z';
  const WORK = 'github.com/acme/work';
  const BEL = String.fromCharCode(7);
  const ATTACHED = {
    specVersion: 9,
    runMode: 'attached',
    controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
    historySyncConsent: { acknowledgedAt: AT, payloadVersion: 3, endpoint: ENDPOINT },
    modelJudgeConsent: { acknowledgedAt: AT, payloadVersion: 1 },
    vaultConsent: { acknowledgedAt: AT, version: 1 },
    onboardedAt: AT,
  } as const;
  const good = { kind: 'repo', identity: WORK, enrolledAt: AT };

  const ONE_BAD_ENTRY: [string, unknown][] = [
    ['an unknown kind', { kind: 'org', identity: 'github.com/acme/other', enrolledAt: AT }],
    [
      'a control character in its label',
      { kind: 'repo', identity: 'github.com/acme/other', label: `work${BEL}`, enrolledAt: AT },
    ],
    [
      'a timestamp that is not one',
      { kind: 'repo', identity: 'github.com/acme/other', enrolledAt: 'yesterday' },
    ],
  ];
  const NOT_A_SCOPE: [string, unknown][] = [
    ['a string', 'enrolled'],
    ['an array', [good]],
    ['entries that is not an array', { endpoint: ENDPOINT, entries: good }],
    ['no endpoint', { entries: [good] }],
  ];
  const GARBLED: [string, unknown][] = [
    ...ONE_BAD_ENTRY.map(([label, bad]): [string, unknown] => [
      `an entry with ${label}`,
      { endpoint: ENDPOINT, entries: [good, bad] },
    ]),
    ...NOT_A_SCOPE,
  ];
  // Wholly valid, and carrying keys this build does not know: what a newer build
  // writes. The readers strip those keys, so a save that normalized the record
  // through them, even only when it is valid, would erase what the newer build
  // wrote. None of the rows above can tell that writer apart from a correct one:
  // each holds something the readers drop, so it is never normalized.
  const FUTURE_SHAPED: [string, unknown][] = [
    [
      'an entry with a key this build does not know',
      { endpoint: ENDPOINT, entries: [{ ...good, futureKey: 1 }] },
    ],
    [
      'a record with a key this build does not know',
      { endpoint: ENDPOINT, entries: [good], futureKey: { nested: [1, 2] } },
    ],
    [
      'unknown keys on the record and on every entry',
      {
        futureKey: 'record',
        endpoint: ENDPOINT,
        entries: [
          { ...good, futureKey: 1 },
          { ...good, identity: 'github.com/acme/app', other: [] },
        ],
      },
    ],
  ];

  /** Every field the attachment and the onboarding are made of, as read back. */
  function expectAttachmentIntact(): void {
    const settings = readWorkspaceSettings(base);
    expect(settings.runMode).toBe('attached');
    expect(settings.controlPlane).toEqual(ATTACHED.controlPlane);
    expect(settings.historySyncConsent).toEqual(ATTACHED.historySyncConsent);
    expect(settings.modelJudgeConsent).toEqual(ATTACHED.modelJudgeConsent);
    expect(settings.vaultConsent).toEqual(ATTACHED.vaultConsent);
    expect(settings.onboardedAt).toBe(AT);
  }

  it.each(ONE_BAD_ENTRY)(
    'drops an entry with %s by itself and keeps the rest of the file',
    (_label, bad) => {
      writeSettings({ ...ATTACHED, attachmentScope: { endpoint: ENDPOINT, entries: [good, bad] } });
      expectAttachmentIntact();
      const scope = parseAttachmentScope(readWorkspaceSettings(base).attachmentScope);
      expect(scope?.entries.map((e) => e.identity)).toEqual([WORK]);
    },
  );

  it.each(NOT_A_SCOPE)(
    'reads %s as no valid scope, which means deny, and keeps the rest of the file',
    (_label, scope) => {
      writeSettings({ ...ATTACHED, attachmentScope: scope });
      expectAttachmentIntact();
      expect(isAttachmentScopeValid(readWorkspaceSettings(base).attachmentScope, ENDPOINT)).toBe(
        false,
      );
    },
  );

  it.each(FUTURE_SHAPED)(
    'reads %s as a valid scope, unknown keys and all, and keeps the rest of the file',
    (_label, scope) => {
      // Pins what makes these rows the ones they are: if the reader refused them
      // they would be one more garbled record, and the save case below would
      // stop testing a writer that normalizes only what it can fully read.
      writeSettings({ ...ATTACHED, attachmentScope: scope });
      expectAttachmentIntact();
      expect(isAttachmentScopeValid(readWorkspaceSettings(base).attachmentScope, ENDPOINT)).toBe(
        true,
      );
    },
  );

  it.each([...GARBLED, ...FUTURE_SHAPED])(
    'survives a save over %s, and so does the attachment',
    (_label, scope) => {
      writeSettings({ ...ATTACHED, attachmentScope: scope });
      applyOnboarding({ policy: 'warn' }, base);

      expectAttachmentIntact();
      const after = readWorkspaceSettings(base);
      expect(after.policy).toBe('warn');
      // Left on disk as it was found: the save is not the place to repair, drop
      // or normalize it. A garbled record kept verbatim still reads as invalid,
      // i.e. deny, and a newer build's keys are still there for it to read.
      expect(after.attachmentScope).toEqual(scope);
      // And in key order, which `toEqual` ignores: the record's JSON text, read
      // back and serialized the same way on both sides, must match. That compares
      // parsed-and-reserialized text, so it pins key order and values, not the
      // file's raw bytes: whitespace and escape spelling are normalized away.
      const onDisk = JSON.parse(readFileSync(join(base, 'settings', 'settings.json'), 'utf8')) as {
        attachmentScope?: unknown;
      };
      expect(JSON.stringify(onDisk.attachmentScope)).toBe(JSON.stringify(scope));
    },
  );
});
