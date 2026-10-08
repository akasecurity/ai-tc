import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import {
  applyOnboarding,
  controlPlaneCredentialPath,
  dataDir as dataDirOf,
  openLocalDatabase,
  readControlPlaneCredentialFile,
  SETTINGS_FILENAME,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { AttachmentMode } from '@akasecurity/schema';
import { attachmentModeOf, connectionRefusalMessage, ManagedSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import type { AttachDeps } from '../../src/commands/attach.ts';
import { parseAttachArgs, runAttach, runDetach, runStatus } from '../../src/commands/attach.ts';
import type { DeviceAttachOutcome } from '../../src/commands/attach-device.ts';
import type { Prompter } from '../../src/lib/prompter.ts';

// What `aka attach` writes once it knows the mode, how it asks about the mode,
// and what it says afterwards; and how `aka detach` clears the enrolled list.
// The pure decision is pinned by the persistence package's own tests. This file
// drives runAttach end to end against a temp home, with the browser path, the
// key verification and the administrator's overlay replaced by recorders.

// Stand-ins, each unarmed by default so every call reaches the real function.
// Armed, the settings write throws, as a full disk would; or, once, another
// writer's change lands just before it, as an `aka enroll` racing the attach
// would. Armed, one numbered credential write throws (counted from the last
// reset, so a case can fail the write-back of a rollback and let the first
// write through), after running a hook that can change the disk first. Armed,
// the history preview answers with counts a case can look for, and every read
// of it is counted.
const stand = vi.hoisted(() => ({
  failSettingsWrite: false,
  credentialWrites: 0,
  failCredentialWriteAt: undefined as number | undefined,
  whenCredentialWriteFails: undefined as (() => void) | undefined,
  beforeNextSettingsWrite: undefined as (() => void) | undefined,
  preview: undefined as { sessions: number; days: number } | undefined,
  previewReads: 0,
}));

vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    applyOnboarding: (
      ...args: Parameters<typeof actual.applyOnboarding>
    ): ReturnType<typeof actual.applyOnboarding> => {
      if (stand.failSettingsWrite) throw new Error('settings write failed');
      // One shot, cleared before it runs, so the write it makes reaches the
      // real function and the call it precedes is the only one it races.
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
        stand.whenCredentialWriteFails?.();
        throw new Error('credential write failed');
      }
      actual.writeControlPlaneCredential(...args);
    },
    readLocalHistoryPreview: (
      ...args: Parameters<typeof actual.readLocalHistoryPreview>
    ): ReturnType<typeof actual.readLocalHistoryPreview> => {
      stand.previewReads += 1;
      return stand.preview ?? actual.readLocalHistoryPreview(...args);
    },
  };
});

const ENDPOINT = 'https://aka.example.com';
const OTHER_ENDPOINT = 'https://aka.example.net';
// An endpoint with a path, and the same one spelled without its last slash.
const PATHED = `${ENDPOINT}/gateway/`;
const PATHED_NO_SLASH = `${ENDPOINT}/gateway`;
const KEY_1 = 'key-1';
const KEY_2 = 'key-2';
// The key an older aka's machine-wide re-attach leaves behind in a case below.
const OLDER_AKA = 'older-aka';
const ISO = '2026-10-01T09:00:00.000Z';
const ADMIN = 'Example IT';
// whoami's answer. The binding compares both fields byte for byte, so any
// printable strings stand in for them.
const ANA = { tenantName: 'Example Org', userEmail: 'member-17' };
const REPO = 'github.com/example-org/payments-api';
const LEDGER = 'github.com/example-org/ledger';
const NEW_REPO = 'github.com/example-org/new-service';

const ACCESS_KEY = 'Access key (input hidden): ';
// The browser path's own question, which the stand-in below asks the way the
// real one does, so the order of questions can be checked.
const DEVICE_CONFIRM = '  Attach this machine to that organization? [y/N] ';
const PERSONAL_DEVICE = 'Is this a personal device? [y/n]: ';
const WIDEN = 'Send activity from anywhere on this machine? [y/N]: ';
// Both causes of the no-terminal refusal, in one message, word for word.
const NEEDS_FLAG =
  'refusing to attach without --scoped or --machine: this machine holds either a credential ' +
  'file aka cannot read, which may be a scoped attachment written by a newer aka, or a scoped ' +
  'attachment to another deployment, and attaching machine-wide without asking could widen ' +
  'what it sends. Re-run with --scoped to send activity only from the repositories you enroll, or with ' +
  '--machine to send activity from anywhere on this machine. Nothing was changed.';
// What a failed save says when it put the earlier credential file back, and what
// it says when it did not, by how it did not.
const LEFT_AS_IT_WAS = 'could not save the attachment; this machine is left as it was.';
const SAVE_FAILED = 'could not save the attachment. ';
const NOTE_REPLACED =
  'The credential file this machine had before could not be read, so it could not be put ' +
  'back, and it is gone. Run `aka attach` again.';
const NOTE_UNTOUCHED =
  'The credential file this machine had before could not be read; this attempt did not change it.';
const NOTE_FAILED =
  'The credential file this machine had before could not be put back, so it may differ ' +
  'from what it was. Run `aka attach` again.';
const NOTE_SUPERSEDED =
  'The credential file changed while this attach was saving, so it was not put back and is ' +
  'left as it is now. Run `aka status` to see what this machine is attached to.';
const CHANGED_WHILE_WAITING =
  "this machine's attachment changed while this command waited, so it was not written over. " +
  'Nothing was changed on this machine; run the command again.';
const SCOPED_HISTORY = 'Send unsent activity from the repositories you enroll? [y/N]: ';
const MACHINE_HISTORY = "Send this machine's unsent activity? [y/N]: ";

// What a personal device still sends, in the one sentence every surface uses
// (the help text, the personal-device question and the attach summary differ
// only in whose policy it is), compared with the line breaks and indentation of
// each surface taken out.
const flat = (text: string): string => text.replace(/\s+/g, ' ');
const REPORT_SENTENCE = (policy: string): string =>
  'Whenever a session starts anywhere on this machine, in a repository or not ' +
  `(a browser chat included), the machine pulls ${policy} policy (at most every 15 minutes) ` +
  'and sends it a device report (at most hourly): a device identifier, host name, ' +
  'versions, detection packs, policy counts, and finding counts and dates for everything ' +
  'recorded on the machine. Where a scan is available (the coding-agent plugins, not a ' +
  'browser chat), the same session start also checks it for device commands.';
// Phrases the sentence replaced, each of which said less than what is sent.
const REPORT_OLD_PHRASES = [
  'across every repository',
  'Any session on this machine',
  'in an enrolled repository or not',
  'on a schedule',
] as const;

const entry = (identity: string) => ({ kind: 'repo', identity, enrolledAt: ISO });
const BOUND = {
  endpoint: ENDPOINT,
  tenantName: ANA.tenantName,
  userEmail: ANA.userEmail,
  entries: [entry(REPO), entry(LEDGER)],
};
/** BOUND as a newer build might leave it: an envelope key, and an entry of a kind this build cannot read. */
const BOUND_AND_NEWER = {
  ...BOUND,
  builtBy: 'a newer build',
  entries: [...BOUND.entries, { kind: 'org', identity: 'example-org', enrolledAt: ISO }],
};
const UNBOUND = { endpoint: ENDPOINT, entries: [entry(REPO)] };
const FRESH = {
  endpoint: ENDPOINT,
  tenantName: ANA.tenantName,
  userEmail: ANA.userEmail,
  entries: [],
};

/** The fleet overlay's shape: the deployment pinned, the mode left alone. */
const planeOnly = (): ManagedSettings =>
  ManagedSettings.parse({ organization: ADMIN, values: { controlPlane: { endpoint: ENDPOINT } } });

const SCOPED_MANAGED = connectionRefusalMessage({ reason: 'scoped-managed', organization: ADMIN });

let base: string;
let exits: number[];

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-attach-write-'));
  exits = [];
});

afterEach(() => {
  stand.failSettingsWrite = false;
  stand.credentialWrites = 0;
  stand.failCredentialWriteAt = undefined;
  stand.whenCredentialWriteFails = undefined;
  stand.beforeNextSettingsWrite = undefined;
  stand.preview = undefined;
  stand.previewReads = 0;
  vi.useRealTimers();
  removeTree(base);
});

interface Script {
  interactive: boolean;
  /** Answers to every question, hidden or not, in the order they are asked. */
  answers?: readonly string[];
  stdin?: string;
  /** What the browser path returns. Not offered unless a case says otherwise. */
  device?: DeviceAttachOutcome;
  /** Who the deployment says the key belongs to; `null` refuses the key. */
  who?: { tenantName: string; userEmail: string } | null;
  /** The administrator's overlay, read each time the attach asks for it. */
  managed?: () => ManagedSettings | null;
  /** Runs while the key is being verified, before the answer comes back. */
  duringVerify?: () => void;
}

/** One run's seams. A question with no scripted answer left fails the run. */
function harness(script: Script) {
  const out: string[] = [];
  const err: string[] = [];
  const asked: string[] = [];
  const calls: string[] = [];
  const answers = [...(script.answers ?? [])];
  let stdinReads = 0;
  const ask = (question: string): Promise<string> => {
    asked.push(question);
    const answer = answers.shift();
    return answer === undefined
      ? Promise.reject(new Error(`unscripted prompt: ${question}`))
      : Promise.resolve(answer);
  };
  const io: Prompter = {
    out: (text) => {
      out.push(text);
    },
    err: (text) => {
      err.push(text);
    },
    isInteractive: script.interactive,
    ask,
    askHidden: ask,
    readAllStdin: () => {
      stdinReads += 1;
      return Promise.resolve(script.stdin ?? '');
    },
  };
  const managed = script.managed ?? (() => null);
  const who = script.who === undefined ? ANA : script.who;
  const deps: AttachDeps = {
    base,
    prompter: io,
    // A getter, so a case can change the overlay while an attach is in flight.
    get managedSettings(): ManagedSettings | null {
      return managed();
    },
    exit: (code) => {
      exits.push(code);
    },
    installBackgroundSync: () => undefined,
    uninstallBackgroundSync: () => undefined,
    deviceAttach: async ({ io: deviceIo }) => {
      calls.push('device');
      const outcome: DeviceAttachOutcome = script.device ?? { kind: 'not-offered' };
      if (outcome.kind === 'attached') await deviceIo.ask(DEVICE_CONFIRM);
      return outcome;
    },
    verify: () => {
      calls.push('verify');
      script.duringVerify?.();
      return who === null ? Promise.reject(new Error('refused')) : Promise.resolve(who);
    },
  };
  return {
    deps,
    asked,
    calls,
    output: () => out.join(''),
    errors: () => err.join(''),
    stdinReads: () => stdinReads,
  };
}

const settingsFile = (): string => join(settingsDirOf(base), SETTINGS_FILENAME);
const credentialFile = (): string => controlPlaneCredentialPath(settingsDirOf(base));

/** settings.json as stored, with no schema between the file and the assertion. */
function storedSettings(): Record<string, unknown> {
  return JSON.parse(readFileSync(settingsFile(), 'utf8')) as Record<string, unknown>;
}

function storedCredential(): Persistence.CredentialFileRead {
  return readControlPlaneCredentialFile(settingsDirOf(base));
}

/** The mode of the credential on disk, or undefined when there is none this build can read. */
function modeOnDisk(): AttachmentMode | undefined {
  const read = storedCredential();
  return read.usable ? attachmentModeOf(read.credential) : undefined;
}

/** A machine attached earlier as a personal device, holding `scope`. */
function attachedScoped(scope: unknown, endpoint = ENDPOINT): void {
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: 2,
    endpoint,
    apiKey: KEY_1,
    mintedAt: ISO,
    mode: 'scoped',
  });
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint, attachedAt: ISO }, attachmentScope: scope },
    base,
    null,
  );
}

/** A credential file a newer build could have written: version 3, which this build cannot read. */
function plantUnreadableCredential(): string {
  mkdirSync(settingsDirOf(base), { recursive: true, mode: 0o700 });
  const bytes = `${JSON.stringify({ specVersion: 3, endpoint: ENDPOINT, apiKey: KEY_1 }, null, 2)}\n`;
  writeFileSync(credentialFile(), bytes, { mode: 0o600 });
  return bytes;
}

/** A symlink where the credential should be, which the reader refuses to follow. */
function plantUntrustedCredential(): void {
  mkdirSync(settingsDirOf(base), { recursive: true, mode: 0o700 });
  const target = join(base, 'elsewhere.json');
  writeFileSync(
    target,
    `${JSON.stringify({ specVersion: 1, endpoint: ENDPOINT, apiKey: KEY_1 })}\n`,
  );
  symlinkSync(target, credentialFile());
}

/** Captures recorded before any attach: one per enrolled key, one for a key nobody enrolled, one with none. */
function seedCaptures(): void {
  const db = openLocalDatabase(dataDirOf(base));
  try {
    db.auditEvents.ensureSessionRoot('s-1', '2026-08-01T00:00:00.000Z');
    for (const [id, key] of [
      ['cap-repo', REPO],
      ['cap-ledger', LEDGER],
      ['cap-new', NEW_REPO],
      ['cap-unkeyed', undefined],
    ] as const) {
      db.auditEvents.insertAuditEvent({
        id,
        eventType: 'prompt',
        rootSessionId: 's-1',
        parentId: 's-1',
        startedAt: '2026-08-01T00:01:00.000Z',
        content: `text of ${id}`,
        ...(key === undefined ? {} : { attributes: { scope_key: key } }),
      });
    }
  } finally {
    db.close();
  }
}

/**
 * Every capture marked to send, read WITHOUT a scope: a scoped writer that
 * marked too much shows up here, where a scoped read would hide it.
 */
function owedCaptures(): string[] {
  const db = openLocalDatabase(dataDirOf(base));
  try {
    return db.historySync
      .pendingCaptureRows(10, Date.now() + 1)
      .map((row) => row.id)
      .sort();
  } finally {
    db.close();
  }
}

const fixture = (path: string): string => readFileSync(new URL(path, import.meta.url), 'utf8');

describe('parseAttachArgs: the mode flags', () => {
  it('reads --scoped and --machine wherever they appear', () => {
    expect(parseAttachArgs(['--url', ENDPOINT, '--scoped'])).toMatchObject({ mode: 'scoped' });
    expect(parseAttachArgs(['--machine', '--url', ENDPOINT])).toMatchObject({ mode: 'machine' });
  });

  it('leaves the mode unset when neither is given', () => {
    expect(parseAttachArgs(['--url', ENDPOINT])).not.toHaveProperty('mode');
  });

  it.each([
    ['--scoped', '--machine'],
    ['--machine', '--scoped'],
  ])('refuses %s together with %s', (first, second) => {
    expect(parseAttachArgs(['--url', ENDPOINT, first, second])).toEqual({
      error: '--scoped and --machine are mutually exclusive',
    });
  });

  it('accepts a flag given twice', () => {
    expect(parseAttachArgs(['--scoped', '--url', ENDPOINT, '--scoped'])).toMatchObject({
      mode: 'scoped',
    });
  });

  it('names both flags in the usage text, with what each sends', async () => {
    const h = harness({ interactive: false });

    await runAttach([], h.deps);

    expect(exits).toEqual([2]);
    expect(h.errors()).toContain('[--scoped | --machine]');
    expect(h.errors()).toContain(
      '  --scoped   A personal device: send activity only from the repositories you',
    );
    expect(h.errors()).toContain(
      '  --machine  A machine your organization owns: send activity from anywhere on\n' +
        '             this machine.',
    );
    // The policy pull, the device report and, where a scan is available, the
    // check for device commands go from a session starting anywhere on the
    // machine, not on a timer, whatever is enrolled; the report's counts are for
    // everything recorded on it, not for the repositories enrolled.
    expect(flat(h.errors())).toContain(REPORT_SENTENCE("the deployment's"));
    for (const phrase of REPORT_OLD_PHRASES) expect(h.errors()).not.toContain(phrase);
    expect(h.errors()).not.toContain('schedule');
    // The usage text names no project anywhere. The machine-wide line says
    // anywhere on this machine because a session outside any repository and a
    // browser chat belong to no project, yet are sent.
    expect(h.errors()).not.toContain('project');
    // The re-attach rule is stated for neither flag, and a flag is said to decide.
    expect(h.errors()).toContain(
      '  With neither flag, a re-attach to the same deployment keeps the mode it has;',
    );
    expect(h.errors()).toContain('With a flag, the flag decides.');
  });
});

describe('aka detach and aka status take no mode flag', () => {
  it.each(['--scoped', '--machine'])('aka detach refuses %s and leaves the attachment', (flag) => {
    attachedScoped(BOUND);
    const h = harness({ interactive: false });

    runDetach([flag], h.deps);

    expect(exits).toEqual([2]);
    expect(h.errors()).toContain('aka detach does not take --scoped or --machine.');
    expect(storedSettings().runMode).toBe('attached');
    expect(storedSettings().attachmentScope).toEqual(BOUND);
    expect(modeOnDisk()).toBe('scoped');
  });

  it.each(['--scoped', '--machine'])('aka status refuses %s', async (flag) => {
    const h = harness({ interactive: false });

    await runStatus([flag], h.deps);

    expect(exits).toEqual([2]);
    expect(h.output()).toBe('');
    expect(h.errors()).toContain('aka status does not take --scoped or --machine.');
  });
});

describe('aka attach refuses before any network call', () => {
  const MANAGED_SHAPES: { name: string; arrange: () => ManagedSettings }[] = [
    { name: 'pins only the deployment', arrange: planeOnly },
    {
      name: 'pins only the mode',
      arrange: () =>
        ManagedSettings.parse({ organization: ADMIN, values: { runMode: 'attached' } }),
    },
    {
      name: 'locks the mode',
      arrange: () => {
        // Attached already: on a standalone machine a lock is refused earlier,
        // as held standalone, and that refusal is not the one under test.
        applyOnboarding(
          { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: ISO } },
          base,
          null,
        );
        return ManagedSettings.parse({ organization: ADMIN, lockedFields: ['runMode'] });
      },
    },
  ];

  it.each(MANAGED_SHAPES)('refuses --scoped when the administrator $name', async ({ arrange }) => {
    const overlay = arrange();
    const h = harness({ interactive: true, managed: () => overlay });

    await runAttach(['--url', ENDPOINT, '--scoped'], h.deps);

    expect(exits).toEqual([2]);
    expect(h.calls).toEqual([]);
    expect(h.asked).toEqual([]);
    expect(h.errors()).toContain(`${SCOPED_MANAGED} Re-run without --scoped.`);
    expect(storedCredential()).toEqual({ usable: false, reason: 'absent' });
  });

  it('reports a machine held at standalone as that, not as a refusal of --scoped', async () => {
    // The lock on a machine that reads as standalone refuses every attach, and
    // that is the more useful thing to be told: a machine-wide attach would be
    // refused for the same reason.
    const overlay = ManagedSettings.parse({ organization: ADMIN, lockedFields: ['runMode'] });
    const h = harness({ interactive: true, managed: () => overlay });

    await runAttach(['--url', ENDPOINT, '--scoped'], h.deps);

    expect(exits).toEqual([2]);
    expect(h.calls).toEqual([]);
    expect(h.errors()).toContain(
      connectionRefusalMessage({ reason: 'held-standalone', organization: ADMIN }),
    );
    expect(h.errors()).not.toContain(SCOPED_MANAGED);
  });

  it('reports a deployment pinned elsewhere as that, not as a refusal of --scoped', async () => {
    const overlay = ManagedSettings.parse({
      organization: ADMIN,
      values: { controlPlane: { endpoint: OTHER_ENDPOINT } },
    });
    const h = harness({ interactive: true, managed: () => overlay });

    await runAttach(['--url', ENDPOINT, '--scoped'], h.deps);

    expect(exits).toEqual([2]);
    expect(h.calls).toEqual([]);
    expect(h.errors()).toContain(
      connectionRefusalMessage({
        reason: 'pinned-endpoint',
        organization: ADMIN,
        endpoint: OTHER_ENDPOINT,
      }),
    );
    expect(h.errors()).not.toContain(SCOPED_MANAGED);
  });

  it('stops a run with no terminal and no flag over a credential file it cannot read', async () => {
    const before = plantUnreadableCredential();
    const h = harness({ interactive: false, stdin: KEY_1 });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([2]);
    expect(h.calls).toEqual([]);
    expect(h.stdinReads()).toBe(0);
    expect(h.errors()).toContain(NEEDS_FLAG);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(before);
  });

  it('stops a run with no terminal and no flag that would point a personal device elsewhere', async () => {
    attachedScoped({ ...BOUND, endpoint: OTHER_ENDPOINT }, OTHER_ENDPOINT);
    const before = readFileSync(credentialFile(), 'utf8');
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([2]);
    expect(h.calls).toEqual([]);
    expect(h.stdinReads()).toBe(0);
    expect(h.errors()).toContain(NEEDS_FLAG);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(before);
    expect(storedSettings().attachmentScope).toEqual({ ...BOUND, endpoint: OTHER_ENDPOINT });
  });

  it('compares the endpoint as typed, so another spelling of it is another deployment', async () => {
    attachedScoped({ ...BOUND, endpoint: PATHED }, PATHED);
    const before = readFileSync(credentialFile(), 'utf8');
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', PATHED_NO_SLASH, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([2]);
    expect(h.calls).toEqual([]);
    expect(h.errors()).toContain(NEEDS_FLAG);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(before);
  });

  it('goes ahead over an unreadable file when --machine says which mode to write', async () => {
    plantUnreadableCredential();
    const h = harness({ interactive: false, stdin: KEY_1 });

    await runAttach(['--url', ENDPOINT, '--machine', '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.calls).toEqual(['verify']);
    expect(storedCredential()).toMatchObject({
      usable: true,
      credential: { specVersion: 1, endpoint: ENDPOINT, apiKey: KEY_1 },
    });
  });

  it('stops before any network call when a file sits where the settings directory should be', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('lstat under a regular file reports ENOENT, not ENOTDIR, on Windows');
      return;
    }
    // The credential read's lstat throws ENOTDIR here: `throwIfNoEntry: false`
    // covers a missing entry only.
    writeFileSync(settingsDirOf(base), 'not a directory');
    const h = harness({ interactive: true });

    await runAttach(['--url', ENDPOINT], h.deps);

    expect(exits).toEqual([1]);
    expect(h.calls).toEqual([]);
    expect(h.asked).toEqual([]);
    expect(h.errors()).toContain('nothing was changed');
  });
});

describe('the personal-device question', () => {
  it('is asked once, after the key verifies, on the key path', async () => {
    const h = harness({ interactive: true, answers: [KEY_1, 'y'] });

    await runAttach(['--url', ENDPOINT, '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.calls).toEqual(['device', 'verify']);
    expect(h.asked).toEqual([ACCESS_KEY, PERSONAL_DEVICE]);
    expect(h.output()).toContain('How much of this machine should AKA send?');
    // True on the scoped answer too: a personal device still pulls policy and
    // sends a device report, so the question never says nothing is sent.
    expect(flat(h.output())).toContain(REPORT_SENTENCE("your organization's"));
    for (const phrase of REPORT_OLD_PHRASES) expect(h.output()).not.toContain(phrase);
    expect(h.output()).toContain(
      '  A machine your organization owns sends activity from anywhere on this',
    );
    expect(h.output()).not.toContain('Nothing is sent');
    expect(h.output()).not.toContain('schedule');
    expect(h.output()).not.toContain('every project');
    expect(modeOnDisk()).toBe('scoped');
    expect(storedSettings().attachmentScope).toEqual(FRESH);
  });

  it('is asked once, after the browser path has confirmed the organization', async () => {
    const h = harness({
      interactive: true,
      answers: ['y', 'n'],
      device: { kind: 'attached', apiKey: KEY_1, identity: ANA },
    });

    await runAttach(['--url', ENDPOINT, '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.calls).toEqual(['device']);
    expect(h.asked).toEqual([DEVICE_CONFIRM, PERSONAL_DEVICE]);
    expect(modeOnDisk()).toBe('machine');
    expect(storedSettings()).not.toHaveProperty('attachmentScope');
  });

  it.each<[string, AttachmentMode]>([
    ['y', 'scoped'],
    ['YES', 'scoped'],
    ['  yes  ', 'scoped'],
    ['n', 'machine'],
    ['No', 'machine'],
  ])('answered %j, attaches %s', async (answer, mode) => {
    const h = harness({ interactive: true, answers: [KEY_1, answer] });

    await runAttach(['--url', ENDPOINT, '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    // Asked: a machine-wide attach with no question is what a run with no
    // terminal does, so the mode on disk alone would not tell the two apart.
    expect(h.asked).toEqual([ACCESS_KEY, PERSONAL_DEVICE]);
    expect(modeOnDisk()).toBe(mode);
  });

  it('has no default: an empty answer, or one that is neither, asks again', async () => {
    const h = harness({ interactive: true, answers: [KEY_1, '', 'maybe', 'n'] });

    await runAttach(['--url', ENDPOINT, '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([ACCESS_KEY, PERSONAL_DEVICE, PERSONAL_DEVICE, PERSONAL_DEVICE]);
    expect(h.output()).toContain(
      'Answer y for a personal device, or n for a machine your organization owns.',
    );
    expect(modeOnDisk()).toBe('machine');
  });

  it('attaches nothing after three answers that are neither yes nor no', async () => {
    const h = harness({ interactive: true, answers: [KEY_1, '', 'maybe', 'sure'] });

    await runAttach(['--url', ENDPOINT, '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.asked).toEqual([ACCESS_KEY, PERSONAL_DEVICE, PERSONAL_DEVICE, PERSONAL_DEVICE]);
    expect(h.errors()).toContain(
      'not attaching: no answer to whether this is a personal device. ' +
        'Nothing was changed on this machine.',
    );
    expect(storedCredential()).toEqual({ usable: false, reason: 'absent' });
    expect(existsSync(settingsFile())).toBe(false);
  });

  it('is never asked about a deployment that refuses the key', async () => {
    const h = harness({ interactive: true, answers: [KEY_1], who: null });

    await runAttach(['--url', ENDPOINT, '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.asked).toEqual([ACCESS_KEY]);
    expect(storedCredential()).toEqual({ usable: false, reason: 'absent' });
  });

  it('is asked on a terminal when a personal device points elsewhere, and the list starts empty', async () => {
    attachedScoped({ ...BOUND, endpoint: OTHER_ENDPOINT }, OTHER_ENDPOINT);
    const h = harness({ interactive: true, answers: [KEY_2, 'y'] });

    await runAttach(['--url', ENDPOINT, '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([ACCESS_KEY, PERSONAL_DEVICE]);
    expect(storedCredential()).toMatchObject({
      usable: true,
      credential: { specVersion: 2, endpoint: ENDPOINT, apiKey: KEY_2, mode: 'scoped' },
    });
    expect(storedSettings().attachmentScope).toEqual(FRESH);
  });
});

describe('a key rotation on a personal device keeps the mode and every enrollment', () => {
  it('through the browser path', async () => {
    attachedScoped(BOUND_AND_NEWER);
    const h = harness({
      interactive: true,
      answers: ['y'],
      device: { kind: 'attached', apiKey: KEY_2, identity: ANA },
    });

    await runAttach(['--url', ENDPOINT, '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.calls).toEqual(['device']);
    expect(h.asked).toEqual([DEVICE_CONFIRM]);
    expect(storedCredential()).toEqual({
      usable: true,
      credential: {
        specVersion: 2,
        endpoint: ENDPOINT,
        apiKey: KEY_2,
        mintedAt: expect.any(String) as string,
        mode: 'scoped',
      },
    });
    // RAW: the envelope key and the entry this build cannot read survive.
    expect(storedSettings().attachmentScope).toEqual(BOUND_AND_NEWER);
    expect(h.output()).toContain('The repositories already enrolled here are kept');
  });

  it('through --key-stdin, with no terminal', async () => {
    attachedScoped(BOUND_AND_NEWER);
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.calls).toEqual(['verify']);
    expect(h.asked).toEqual([]);
    expect(storedCredential()).toMatchObject({
      usable: true,
      credential: { specVersion: 2, endpoint: ENDPOINT, apiKey: KEY_2, mode: 'scoped' },
    });
    expect(storedSettings().attachmentScope).toEqual(BOUND_AND_NEWER);
  });

  it('for an endpoint with a path, compared and stored as typed', async () => {
    attachedScoped({ ...BOUND, endpoint: PATHED }, PATHED);
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', PATHED, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(storedCredential()).toMatchObject({
      usable: true,
      credential: { specVersion: 2, endpoint: PATHED, apiKey: KEY_2, mode: 'scoped' },
    });
    expect(storedSettings().attachmentScope).toEqual({ ...BOUND, endpoint: PATHED });
  });

  it('says nothing is enrolled when the list it kept holds nothing', async () => {
    // A rotation before anything was enrolled: the record is kept, and is empty.
    attachedScoped(FRESH);
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(storedSettings().attachmentScope).toEqual(FRESH);
    expect(h.output()).toContain(
      'Nothing is enrolled yet. Run `aka enroll` in a repository to start sending it.',
    );
    expect(h.output()).not.toContain('already enrolled here are kept');
  });

  it('judges the list inside the settings lock, so an enrollment that lands first is kept', async () => {
    attachedScoped(BOUND);
    // Lands after the attach has verified and decided, immediately before its
    // own settings write takes the lock, as `aka enroll` racing it would.
    stand.beforeNextSettingsWrite = () => {
      applyOnboarding(
        (current) => ({
          attachmentScope: {
            ...(current.attachmentScope as Record<string, unknown>),
            entries: [...BOUND.entries, entry(NEW_REPO)],
          },
        }),
        base,
        null,
      );
    };
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(modeOnDisk()).toBe('scoped');
    expect(storedSettings().attachmentScope).toEqual({
      ...BOUND,
      entries: [...BOUND.entries, entry(NEW_REPO)],
    });
  });
});

describe('widening a personal device with --machine', () => {
  it('asks first on a terminal, then attaches machine-wide and clears the list', async () => {
    attachedScoped(BOUND);
    const h = harness({ interactive: true, answers: [KEY_2, 'y'] });

    await runAttach(['--url', ENDPOINT, '--machine', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([ACCESS_KEY, WIDEN]);
    expect(h.output()).toContain(
      `This machine is attached to ${ENDPOINT} as a personal device: activity is`,
    );
    expect(h.output()).toContain(
      'sent only from the repositories enrolled on it. With --machine, activity from',
    );
    expect(h.output()).toContain(
      'anywhere on this machine is sent, and the enrolled list is cleared.',
    );
    expect(h.output()).not.toContain('every project');
    expect(storedCredential()).toMatchObject({
      usable: true,
      credential: { specVersion: 1, endpoint: ENDPOINT, apiKey: KEY_2 },
    });
    expect(storedSettings()).not.toHaveProperty('attachmentScope');
  });

  it('changes nothing when the widening is declined', async () => {
    attachedScoped(BOUND);
    const credentialBefore = readFileSync(credentialFile(), 'utf8');
    const settingsBefore = readFileSync(settingsFile(), 'utf8');
    const h = harness({ interactive: true, answers: [KEY_2, ''] });

    await runAttach(['--url', ENDPOINT, '--machine', '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    // Asked after verification, like every question here.
    expect(h.calls).toEqual(['device', 'verify']);
    expect(h.errors()).toContain(
      'not attaching machine-wide. Nothing was changed on this machine.',
    );
    expect(readFileSync(credentialFile(), 'utf8')).toBe(credentialBefore);
    expect(readFileSync(settingsFile(), 'utf8')).toBe(settingsBefore);
  });

  it('takes the flag as the answer without a terminal, and says what it does', async () => {
    attachedScoped(BOUND);
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', ENDPOINT, '--machine', '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([]);
    expect(h.output()).toContain(
      `Attaching machine-wide, as --machine asks. This machine was attached to ${ENDPOINT} ` +
        'as a personal device; its enrolled list will be cleared.',
    );
    expect(modeOnDisk()).toBe('machine');
    expect(storedSettings()).not.toHaveProperty('attachmentScope');
  });

  it('leaves nothing for a later --scoped to revive', async () => {
    attachedScoped(BOUND);
    const widen = harness({ interactive: false, stdin: KEY_2 });
    await runAttach(
      ['--url', ENDPOINT, '--machine', '--key-stdin', '--no-sync-history'],
      widen.deps,
    );
    // Cleared by the machine-wide attach itself. The later scoped attach starts
    // a fresh list whatever it finds, so only this assertion can fail for that.
    expect(storedSettings()).not.toHaveProperty('attachmentScope');

    const narrow = harness({ interactive: false, stdin: KEY_1 });
    await runAttach(
      ['--url', ENDPOINT, '--scoped', '--key-stdin', '--no-sync-history'],
      narrow.deps,
    );

    expect(exits).toEqual([]);
    expect(modeOnDisk()).toBe('scoped');
    expect(storedSettings().attachmentScope).toEqual(FRESH);
  });

  it('is neither refused nor asked about when the personal device was attached to another deployment', async () => {
    // Nothing was being sent to this deployment, so attaching to it machine-wide
    // widens nothing here. The list for the other deployment goes with the
    // credential it belonged to.
    attachedScoped({ ...BOUND, endpoint: OTHER_ENDPOINT }, OTHER_ENDPOINT);
    const h = harness({ interactive: true, answers: [KEY_2] });

    await runAttach(['--url', ENDPOINT, '--machine', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([ACCESS_KEY]);
    expect(h.output()).not.toContain('personal device');
    expect(storedCredential()).toMatchObject({
      usable: true,
      credential: { specVersion: 1, endpoint: ENDPOINT, apiKey: KEY_2 },
    });
    expect(storedSettings()).not.toHaveProperty('attachmentScope');
  });

  it('asks first when --machine names the deployment with a trailing slash', async () => {
    attachedScoped(BOUND);
    const h = harness({ interactive: true, answers: [KEY_2, 'y'] });

    await runAttach(['--url', `${ENDPOINT}/`, '--machine', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([ACCESS_KEY, WIDEN]);
    expect(h.output()).toContain(
      `This machine is attached to ${ENDPOINT}/ as a personal device: activity is`,
    );
    expect(storedCredential()).toMatchObject({
      usable: true,
      credential: { specVersion: 1, endpoint: `${ENDPOINT}/`, apiKey: KEY_2 },
    });
    expect(storedSettings()).not.toHaveProperty('attachmentScope');
  });

  it('says what it does without a terminal when --machine names the host in another case', async () => {
    attachedScoped(BOUND);
    const typed = 'https://AKA.example.com';
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', typed, '--machine', '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.output()).toContain(
      `Attaching machine-wide, as --machine asks. This machine was attached to ${typed} ` +
        'as a personal device; its enrolled list will be cleared.',
    );
  });
});

describe('an attach is not written over what changed while it waited', () => {
  // The mode is decided before the key is verified, and a browser approval can
  // take minutes. Another aka may attach this machine as a personal device in
  // that time; writing machine-wide over it would widen it with nobody asked.
  it.each<[string, string[], boolean, string[]]>([
    ['--machine and no terminal', ['--machine', '--key-stdin'], false, []],
    ['no flag and no terminal', ['--key-stdin'], false, []],
    ['no flag, and the answer "no" to the personal-device question', [], true, ['n']],
  ])('a personal device appeared: %s', async (_how, flags, interactive, answers) => {
    const script = {
      interactive,
      answers: interactive ? [KEY_2, ...answers] : [],
      stdin: KEY_2,
      duringVerify: () => {
        attachedScoped(BOUND);
      },
    };
    const h = harness(script);

    await runAttach(['--url', ENDPOINT, ...flags, '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.errors()).toContain(CHANGED_WHILE_WAITING);
    expect(h.errors()).not.toContain(LEFT_AS_IT_WAS);
    // Untouched: the credential and the list the other attach left.
    expect(storedCredential()).toMatchObject({
      usable: true,
      credential: { specVersion: 2, endpoint: ENDPOINT, apiKey: KEY_1, mode: 'scoped' },
    });
    expect(storedSettings().attachmentScope).toEqual(BOUND);
  });

  it('a credential file this build cannot read appeared, on a run with no terminal', async () => {
    // A newer build's file, possibly a scoped attachment: the run had no flag to
    // say it should be written over, and decided machine-wide when there was none.
    let planted = '';
    const h = harness({
      interactive: false,
      stdin: KEY_2,
      duringVerify: () => {
        planted = plantUnreadableCredential();
      },
    });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.errors()).toContain(CHANGED_WHILE_WAITING);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(planted);
    expect(existsSync(settingsFile())).toBe(false);
  });

  it('a machine-wide credential became one this build cannot read, on a terminal with no flag', async () => {
    // Settled as a rotation that needs no question; what is on disk now is a
    // file the decision would ask about, so the answer to a question nobody was
    // asked cannot be assumed.
    writeControlPlaneCredential(settingsDirOf(base), {
      specVersion: 1,
      endpoint: ENDPOINT,
      apiKey: KEY_1,
      mintedAt: ISO,
    });
    let planted = '';
    const h = harness({
      interactive: true,
      answers: [KEY_2],
      duringVerify: () => {
        planted = plantUnreadableCredential();
      },
    });

    await runAttach(['--url', ENDPOINT, '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.asked).toEqual([ACCESS_KEY]);
    expect(h.errors()).toContain(CHANGED_WHILE_WAITING);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(planted);
  });

  it('an older aka re-attached the machine machine-wide, on a rotation of a personal device', async () => {
    attachedScoped(BOUND);
    // An older aka writes a version-1 credential and leaves the list beside it.
    const h = harness({
      interactive: false,
      stdin: KEY_2,
      duringVerify: () => {
        writeControlPlaneCredential(settingsDirOf(base), {
          specVersion: 1,
          endpoint: ENDPOINT,
          apiKey: OLDER_AKA,
          mintedAt: ISO,
        });
      },
    });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.errors()).toContain(CHANGED_WHILE_WAITING);
    expect(storedCredential()).toMatchObject({
      usable: true,
      credential: { specVersion: 1, apiKey: OLDER_AKA },
    });
    expect(storedSettings().attachmentScope).toEqual(BOUND);
  });

  it('an older aka re-attached the machine machine-wide, on a --scoped attach: the list is not kept', async () => {
    attachedScoped(BOUND);
    const h = harness({
      interactive: false,
      stdin: KEY_2,
      duringVerify: () => {
        writeControlPlaneCredential(settingsDirOf(base), {
          specVersion: 1,
          endpoint: ENDPOINT,
          apiKey: OLDER_AKA,
          mintedAt: ISO,
        });
      },
    });

    await runAttach(['--url', ENDPOINT, '--scoped', '--key-stdin', '--no-sync-history'], h.deps);

    // --scoped narrows, so it goes ahead; but the list beside a machine-wide
    // credential belongs to an attachment that has ended, so it starts empty.
    expect(exits).toEqual([]);
    expect(modeOnDisk()).toBe('scoped');
    expect(storedSettings().attachmentScope).toEqual(FRESH);
  });

  it('the personal device was detached, on a rotation of it', async () => {
    attachedScoped(BOUND);
    const h = harness({
      interactive: false,
      stdin: KEY_2,
      duringVerify: () => {
        rmSync(credentialFile());
      },
    });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.errors()).toContain(CHANGED_WHILE_WAITING);
    expect(storedCredential()).toEqual({ usable: false, reason: 'absent' });
  });

  it('a file took the settings directory place', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('lstat under a regular file reports ENOENT, not ENOTDIR, on Windows');
      return;
    }
    // The early read passed; the read just before the writes meets the file.
    const h = harness({
      interactive: false,
      stdin: KEY_1,
      duringVerify: () => {
        writeFileSync(settingsDirOf(base), 'not a directory');
      },
    });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.calls).toEqual(['verify']);
    expect(h.errors()).toContain('nothing was changed on this machine');
    expect(existsSync(credentialFile())).toBe(false);
  });
});

describe('the enrolled list is kept only for the organization and account that built it', () => {
  it.each([
    ['another organization', { ...ANA, tenantName: 'Other Org' }],
    ['another account', { ...ANA, userEmail: 'member-18' }],
  ])('starts empty when the key verifies as %s', async (_label, who) => {
    attachedScoped(BOUND);
    const h = harness({ interactive: false, stdin: KEY_2, who });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(modeOnDisk()).toBe('scoped');
    expect(storedSettings().attachmentScope).toEqual({
      endpoint: ENDPOINT,
      tenantName: who.tenantName,
      userEmail: who.userEmail,
      entries: [],
    });
    expect(h.output()).toContain(
      'Nothing is enrolled yet. Run `aka enroll` in a repository to start sending it.',
    );
  });

  it('starts empty over a list that names nobody, which cannot be checked', async () => {
    attachedScoped(UNBOUND);
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(storedSettings().attachmentScope).toEqual(FRESH);
  });

  it.each<[string, () => void]>([
    [
      'beside a machine-wide credential, as an older re-attach leaves it',
      () => {
        writeControlPlaneCredential(settingsDirOf(base), {
          specVersion: 1,
          endpoint: ENDPOINT,
          apiKey: KEY_1,
          mintedAt: ISO,
        });
        applyOnboarding(
          {
            runMode: 'attached',
            controlPlane: { endpoint: ENDPOINT, attachedAt: ISO },
            attachmentScope: BOUND,
          },
          base,
          null,
        );
      },
    ],
    [
      'with no credential, as an older detach leaves it',
      () => {
        applyOnboarding({ runMode: 'standalone', attachmentScope: BOUND }, base, null);
      },
    ],
  ])('starts empty over a bound list left %s', async (_how, arrange) => {
    arrange();
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', ENDPOINT, '--scoped', '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(modeOnDisk()).toBe('scoped');
    expect(storedSettings().attachmentScope).toEqual(FRESH);
  });
});

describe('a machine an administrator manages attaches machine-wide', () => {
  it('asks nothing on a first attach', async () => {
    const overlay = planeOnly();
    const h = harness({
      interactive: true,
      answers: ['y'],
      device: { kind: 'attached', apiKey: KEY_1, identity: ANA },
      managed: () => overlay,
    });

    await runAttach(['--url', ENDPOINT, '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([DEVICE_CONFIRM]);
    expect(modeOnDisk()).toBe('machine');
    expect(h.output()).not.toContain('personal device');
    expect(storedSettings()).not.toHaveProperty('attachmentScope');
  });

  it('widens a personal device that became managed, with one line and no question', async () => {
    attachedScoped(BOUND);
    const overlay = planeOnly();
    const h = harness({
      interactive: true,
      answers: ['y'],
      device: { kind: 'attached', apiKey: KEY_2, identity: ANA },
      managed: () => overlay,
    });

    await runAttach(['--url', ENDPOINT, '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([DEVICE_CONFIRM]);
    expect(h.output()).toContain(
      `${SCOPED_MANAGED} This machine was attached to ${ENDPOINT} as a personal device; ` +
        'its enrolled list will be cleared.',
    );
    expect(storedCredential()).toMatchObject({
      usable: true,
      credential: { specVersion: 1, endpoint: ENDPOINT, apiKey: KEY_2 },
    });
    expect(storedSettings()).not.toHaveProperty('attachmentScope');
  });

  it('asks nothing of a managed --machine over a personal device, even with a terminal', async () => {
    // The typed flag would be a widening to confirm on an unmanaged machine;
    // here the administrator decided, so the line is information and not a question.
    attachedScoped(BOUND);
    const overlay = planeOnly();
    const h = harness({ interactive: true, answers: [KEY_2], managed: () => overlay });

    await runAttach(['--url', ENDPOINT, '--machine', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([ACCESS_KEY]);
    expect(h.output()).toContain(SCOPED_MANAGED);
    expect(h.output()).not.toContain('Attaching machine-wide, as --machine asks.');
    expect(modeOnDisk()).toBe('machine');
  });

  it('says why when a personal device attached to another deployment attaches here managed', async () => {
    // The mode pinned and nothing else: the attach to a new deployment is not
    // refused, and the machine is no longer the user's to scope.
    attachedScoped({ ...BOUND, endpoint: OTHER_ENDPOINT }, OTHER_ENDPOINT);
    const overlay = ManagedSettings.parse({ organization: ADMIN, values: { runMode: 'attached' } });
    const h = harness({ interactive: false, stdin: KEY_2, managed: () => overlay });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.output()).toContain(
      `${SCOPED_MANAGED} This machine was attached to another deployment as a personal device; ` +
        'its enrolled list will be cleared.',
    );
    // The other deployment is read from disk and never echoed.
    expect(h.output()).not.toContain(OTHER_ENDPOINT);
    expect(storedCredential()).toMatchObject({
      usable: true,
      credential: { specVersion: 1, endpoint: ENDPOINT, apiKey: KEY_2 },
    });
    expect(storedSettings()).not.toHaveProperty('attachmentScope');
  });

  it('names the widening of a personal device attached to another spelling of this deployment', async () => {
    attachedScoped(BOUND);
    const overlay = ManagedSettings.parse({ organization: ADMIN, values: { runMode: 'attached' } });
    const h = harness({ interactive: false, stdin: KEY_2, managed: () => overlay });

    await runAttach(['--url', `${ENDPOINT}/`, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.output()).toContain(
      `${SCOPED_MANAGED} This machine was attached to ${ENDPOINT}/ as a personal device; ` +
        'its enrolled list will be cleared.',
    );
    expect(h.output()).not.toContain('another deployment');
  });

  it('refuses a scoped write on a machine that became managed while it waited', async () => {
    let overlay: ManagedSettings | null = null;
    const h = harness({
      interactive: false,
      stdin: KEY_1,
      managed: () => overlay,
      duringVerify: () => {
        overlay = planeOnly();
      },
    });

    await runAttach(['--url', ENDPOINT, '--scoped', '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.calls).toEqual(['verify']);
    expect(h.errors()).toContain(`${SCOPED_MANAGED} Nothing was changed on this machine.`);
    expect(storedCredential()).toEqual({ usable: false, reason: 'absent' });
  });
});

describe('what a machine attach writes', () => {
  // The values the persistence suite's fixture was captured with, from the
  // writer as it stood before scoped attachments existed.
  const FIXTURE_ENDPOINT = 'https://cp.example';
  const FIXTURE_KEY = 'placeholder';
  const FIXTURE_MINTED_AT = '2026-10-01T00:00:00.000Z';

  it.each<[string, string[]]>([
    ['with --machine', ['--machine']],
    ['with no flag and no terminal', []],
  ])(
    'writes the version-1 bytes every attach wrote before modes existed, %s',
    async (_how, flags) => {
      vi.useFakeTimers({ toFake: ['Date'], now: new Date(FIXTURE_MINTED_AT) });
      const h = harness({ interactive: false, stdin: FIXTURE_KEY });

      await runAttach(
        ['--url', FIXTURE_ENDPOINT, ...flags, '--key-stdin', '--no-sync-history'],
        h.deps,
      );

      expect(exits).toEqual([]);
      expect(readFileSync(credentialFile(), 'utf8')).toBe(
        fixture('../../../packages/persistence/test/fixtures/machine-credential-v1.json'),
      );
      expect(storedSettings()).not.toHaveProperty('attachmentScope');
    },
  );
});

describe('a save that fails puts the credential file back as it was, or says it could not', () => {
  interface Earlier {
    name: string;
    /** Flags that choose the mode; none keeps the mode the credential already holds. */
    flags: string[];
    /** The row needs POSIX behaviour (a directory or a symlink in the file's place). */
    posixOnly?: boolean;
    /** Plants the earlier file and returns its bytes when it is a regular file. */
    plant: () => string | undefined;
    /** What is on disk afterwards, given the bytes that were planted. */
    onDisk: (planted: string | undefined) => void;
    /** What the failed save says. */
    says: string;
  }

  const sameBytes = (planted: string | undefined): void => {
    expect(readFileSync(credentialFile(), 'utf8')).toBe(planted);
  };
  const plantFile = (text: string): string => {
    mkdirSync(settingsDirOf(base), { recursive: true, mode: 0o700 });
    writeFileSync(credentialFile(), text, { mode: 0o600 });
    return text;
  };

  const EARLIER: Earlier[] = [
    {
      name: 'no file',
      flags: ['--machine'],
      plant: () => undefined,
      onDisk: () => {
        expect(storedCredential()).toEqual({ usable: false, reason: 'absent' });
      },
      says: LEFT_AS_IT_WAS,
    },
    {
      name: 'a machine-wide credential',
      flags: [],
      plant: () => {
        writeControlPlaneCredential(settingsDirOf(base), {
          specVersion: 1,
          endpoint: ENDPOINT,
          apiKey: KEY_1,
          mintedAt: ISO,
        });
        return readFileSync(credentialFile(), 'utf8');
      },
      onDisk: sameBytes,
      says: LEFT_AS_IT_WAS,
    },
    {
      name: 'a scoped credential',
      flags: [],
      plant: () => {
        attachedScoped(BOUND);
        return readFileSync(credentialFile(), 'utf8');
      },
      onDisk: sameBytes,
      says: LEFT_AS_IT_WAS,
    },
    {
      name: 'a file that is not JSON',
      flags: ['--machine'],
      plant: () => plantFile('{ not json\n'),
      onDisk: sameBytes,
      says: LEFT_AS_IT_WAS,
    },
    {
      // It may be a newer build's scoped credential. --machine lets the attach go
      // ahead over it; a failed write must not then delete it.
      name: 'a credential from a newer version',
      flags: ['--machine'],
      plant: plantUnreadableCredential,
      onDisk: sameBytes,
      says: LEFT_AS_IT_WAS,
    },
    {
      name: 'a credential for an endpoint no key is sent to',
      flags: ['--machine'],
      plant: () =>
        plantFile(
          `${JSON.stringify({ specVersion: 1, endpoint: 'http://aka.example.org', apiKey: KEY_1, mintedAt: ISO }, null, 2)}\n`,
        ),
      onDisk: sameBytes,
      says: LEFT_AS_IT_WAS,
    },
    {
      // The credential write cannot replace a directory, so it fails before the
      // settings write is reached, and the directory is as it was.
      name: 'a directory where the file should be',
      flags: ['--machine'],
      posixOnly: true,
      plant: () => {
        mkdirSync(credentialFile(), { recursive: true });
        return undefined;
      },
      onDisk: () => {
        expect(lstatSync(credentialFile()).isDirectory()).toBe(true);
      },
      says: `${SAVE_FAILED}${NOTE_UNTOUCHED}`,
    },
    {
      // A symlink is never followed, so there are no bytes to put back, and the
      // new credential replaced the link itself.
      name: 'a symlink where the file should be',
      flags: ['--machine'],
      posixOnly: true,
      plant: () => {
        plantUntrustedCredential();
        return undefined;
      },
      onDisk: () => {
        expect(lstatSync(credentialFile(), { throwIfNoEntry: false })).toBeUndefined();
      },
      says: `${SAVE_FAILED}${NOTE_REPLACED}`,
    },
  ];

  it.for(EARLIER)('with $name before it', async (row, ctx) => {
    if (row.posixOnly === true && process.platform === 'win32') {
      ctx.skip('a directory or a symlink in the file place is a POSIX arrangement');
      return;
    }
    const planted = row.plant();
    stand.failSettingsWrite = true;
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', ENDPOINT, ...row.flags, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.errors()).toContain(row.says);
    if (row.says !== LEFT_AS_IT_WAS) expect(h.errors()).not.toContain(LEFT_AS_IT_WAS);
    row.onDisk(planted);
  });

  it.each<[string, () => void]>([
    [
      'a machine-wide credential',
      () => {
        writeControlPlaneCredential(settingsDirOf(base), {
          specVersion: 1,
          endpoint: ENDPOINT,
          apiKey: KEY_1,
          mintedAt: ISO,
        });
        applyOnboarding(
          { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: ISO } },
          base,
          null,
        );
      },
    ],
    ['no credential', () => undefined],
  ])(
    'leaves a personal device another attach made while this one was saving, over %s',
    async (_name, arrange) => {
      arrange();
      // Lands after this attach wrote its credential and just before its settings
      // write, which then fails: a second attach that won the race.
      stand.beforeNextSettingsWrite = () => {
        attachedScoped(BOUND);
        throw new Error('settings write failed');
      };
      const h = harness({ interactive: false, stdin: KEY_2 });

      await runAttach(['--url', ENDPOINT, '--machine', '--key-stdin', '--no-sync-history'], h.deps);

      expect(exits).toEqual([1]);
      expect(h.errors()).toContain(`${SAVE_FAILED}${NOTE_SUPERSEDED}`);
      expect(h.errors()).not.toContain(LEFT_AS_IT_WAS);
      expect(storedCredential()).toEqual({
        usable: true,
        credential: {
          specVersion: 2,
          endpoint: ENDPOINT,
          apiKey: KEY_1,
          mintedAt: ISO,
          mode: 'scoped',
        },
      });
      expect(storedSettings().attachmentScope).toEqual(BOUND);
    },
  );

  it('writes nothing back, and says the machine is as it was, when its own credential write never landed', async () => {
    writeControlPlaneCredential(settingsDirOf(base), {
      specVersion: 1,
      endpoint: ENDPOINT,
      apiKey: KEY_1,
      mintedAt: ISO,
    });
    const before = readFileSync(credentialFile(), 'utf8');
    stand.credentialWrites = 0;
    stand.failCredentialWriteAt = 1;
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', ENDPOINT, '--machine', '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.errors()).toContain(LEFT_AS_IT_WAS);
    // The failed write was the only one: the file already held the earlier credential.
    expect(stand.credentialWrites).toBe(1);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(before);
  });

  it('puts an unreadable credential file back owner-only', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    plantUnreadableCredential();
    stand.failSettingsWrite = true;
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', ENDPOINT, '--machine', '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(statSync(credentialFile()).mode & 0o777).toBe(0o600);
  });

  it('says so when the earlier credential cannot be written back', async () => {
    attachedScoped(BOUND);
    // The attach's own write goes through; the write that would put the earlier
    // credential back is the second, and it fails.
    stand.credentialWrites = 0;
    stand.failCredentialWriteAt = 2;
    stand.failSettingsWrite = true;
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.errors()).toContain(`${SAVE_FAILED}${NOTE_FAILED}`);
    expect(h.errors()).not.toContain(LEFT_AS_IT_WAS);
    // What the line means: the file on disk is the attach's, not the earlier one.
    expect(storedCredential()).toMatchObject({ usable: true, credential: { apiKey: KEY_2 } });
  });

  describe('when the administrator froze the mode after the checks', () => {
    const FROZEN = (): ManagedSettings =>
      ManagedSettings.parse({ organization: ADMIN, lockedFields: ['runMode'] });
    const REFUSED =
      'your organization manages this setting on this machine, so it cannot be attached here.';

    // Half attached: a credential and no settings that say so, so the machine
    // reads as standalone and the lock only bites at the settings write.
    const arrange = (): { overlay: () => ManagedSettings | null; freeze: () => void } => {
      let overlay: ManagedSettings | null = null;
      writeControlPlaneCredential(settingsDirOf(base), {
        specVersion: 1,
        endpoint: ENDPOINT,
        apiKey: KEY_1,
        mintedAt: ISO,
      });
      return {
        overlay: () => overlay,
        freeze: () => {
          overlay = FROZEN();
        },
      };
    };

    it('reports the refusal and puts the earlier credential back', async () => {
      const { overlay, freeze } = arrange();
      const before = readFileSync(credentialFile(), 'utf8');
      const h = harness({
        interactive: false,
        stdin: KEY_2,
        managed: overlay,
        duringVerify: freeze,
      });

      await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

      expect(exits).toEqual([1]);
      expect(h.errors()).toContain(REFUSED);
      expect(h.errors()).not.toContain('could not be put back');
      expect(readFileSync(credentialFile(), 'utf8')).toBe(before);
    });

    it('also says so when the earlier credential cannot be put back', async () => {
      const { overlay, freeze } = arrange();
      stand.credentialWrites = 0;
      stand.failCredentialWriteAt = 2;
      const h = harness({
        interactive: false,
        stdin: KEY_2,
        managed: overlay,
        duringVerify: freeze,
      });

      await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

      expect(exits).toEqual([1]);
      expect(h.errors()).toContain(`${REFUSED} ${NOTE_FAILED}`);
    });
  });
});

describe('a credential write that fails', () => {
  it.skipIf(process.platform === 'win32')(
    'leaves an earlier file it could not read alone, and says it did not change it',
    async () => {
      plantUntrustedCredential();
      stand.credentialWrites = 0;
      stand.failCredentialWriteAt = 1;
      const h = harness({ interactive: false, stdin: KEY_2 });

      await runAttach(['--url', ENDPOINT, '--machine', '--key-stdin', '--no-sync-history'], h.deps);

      expect(exits).toEqual([1]);
      expect(h.errors()).toContain(`${SAVE_FAILED}${NOTE_UNTOUCHED}`);
      // The link is still there: the rollback removes only a file this attach wrote.
      expect(lstatSync(credentialFile()).isSymbolicLink()).toBe(true);
    },
  );

  it.skipIf(process.platform === 'win32')(
    'does not remove a credential with the same key that this attach did not write',
    async () => {
      plantUntrustedCredential();
      // Another writer puts a usable credential with the same key in the file's
      // place while this attach's write is failing. It is not this attach's file.
      stand.whenCredentialWriteFails = () => {
        rmSync(credentialFile());
        writeControlPlaneCredential(settingsDirOf(base), {
          specVersion: 1,
          endpoint: ENDPOINT,
          apiKey: KEY_2,
          mintedAt: ISO,
        });
      };
      stand.credentialWrites = 0;
      stand.failCredentialWriteAt = 1;
      const h = harness({ interactive: false, stdin: KEY_2 });

      await runAttach(['--url', ENDPOINT, '--machine', '--key-stdin', '--no-sync-history'], h.deps);

      expect(exits).toEqual([1]);
      expect(h.errors()).toContain(`${SAVE_FAILED}${NOTE_UNTOUCHED}`);
      expect(storedCredential()).toEqual({
        usable: true,
        credential: { specVersion: 1, endpoint: ENDPOINT, apiKey: KEY_2, mintedAt: ISO },
      });
    },
  );
});

describe('what a scoped attach writes', () => {
  it('writes the version-2 bytes the frozen-reader suite reads', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: new Date(ISO) });
    const h = harness({ interactive: false, stdin: KEY_1 });

    await runAttach(['--url', ENDPOINT, '--scoped', '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(
      fixture('../../../packages/plugin-sdk/test/fixtures/cli-scoped-credential-v2.json'),
    );
    expect(storedSettings().attachmentScope).toEqual(FRESH);
  });

  it('puts the mode where the reader returns it, so writing back what was read gives the same bytes', async () => {
    const h = harness({ interactive: false, stdin: KEY_1 });

    await runAttach(['--url', ENDPOINT, '--scoped', '--key-stdin', '--no-sync-history'], h.deps);

    const bytes = readFileSync(credentialFile(), 'utf8');
    const read = storedCredential();
    if (!read.usable) throw new Error(`expected a usable credential, got ${read.reason}`);
    // Through the writer, as a rollback does, rather than a second statement of
    // how it serialises.
    const again = settingsDirOf(join(base, 'again'));
    writeControlPlaneCredential(again, read.credential);
    expect(readFileSync(controlPlaneCredentialPath(again), 'utf8')).toBe(bytes);
  });

  it('puts back the scoped credential byte for byte when the settings write fails', async () => {
    const first = harness({ interactive: false, stdin: KEY_1 });
    await runAttach(
      ['--url', ENDPOINT, '--scoped', '--key-stdin', '--no-sync-history'],
      first.deps,
    );
    const before = readFileSync(credentialFile(), 'utf8');
    expect(before).toContain('"mode": "scoped"');

    stand.failSettingsWrite = true;
    const second = harness({ interactive: false, stdin: KEY_2 });
    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], second.deps);

    expect(exits).toEqual([1]);
    expect(second.errors()).toContain(LEFT_AS_IT_WAS);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(before);
  });
});

describe('what an attach granted --sync-history marks to send of what was recorded before it', () => {
  it('marks nothing on a first attach as a personal device, since nothing is enrolled', async () => {
    seedCaptures();
    const h = harness({ interactive: false, stdin: KEY_1 });

    await runAttach(['--url', ENDPOINT, '--scoped', '--key-stdin', '--sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(storedSettings().historySyncConsent).toMatchObject({ endpoint: ENDPOINT });
    expect(owedCaptures()).toEqual([]);
  });

  it('marks only the enrolled repositories on a key rotation of a personal device', async () => {
    seedCaptures();
    attachedScoped(BOUND);
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(modeOnDisk()).toBe('scoped');
    expect(owedCaptures()).toEqual(['cap-ledger', 'cap-repo']);
  });

  // The control: the unscoped read sees every mark a machine-wide grant makes,
  // so the empty answer above is not a read that sees nothing.
  it('marks every capture on a machine-wide attach', async () => {
    seedCaptures();
    const h = harness({ interactive: false, stdin: KEY_1 });

    await runAttach(['--url', ENDPOINT, '--machine', '--key-stdin', '--sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(owedCaptures()).toEqual(['cap-ledger', 'cap-new', 'cap-repo', 'cap-unkeyed']);
  });
});

describe('aka detach', () => {
  it('clears the enrolled list, so a later scoped attach as the same account starts empty', async () => {
    attachedScoped(BOUND);
    const detach = harness({ interactive: false });

    runDetach([], detach.deps);

    expect(exits).toEqual([]);
    expect(storedSettings().runMode).toBe('standalone');
    expect(storedSettings()).not.toHaveProperty('attachmentScope');

    const again = harness({ interactive: false, stdin: KEY_2 });
    await runAttach(
      ['--url', ENDPOINT, '--scoped', '--key-stdin', '--no-sync-history'],
      again.deps,
    );

    expect(exits).toEqual([]);
    expect(storedSettings().attachmentScope).toEqual(FRESH);
  });
});

describe('what an attach says', () => {
  it('says on a personal device that only enrolled repositories are sent, and how to enroll one', async () => {
    const h = harness({ interactive: false, stdin: KEY_1 });

    await runAttach(['--url', ENDPOINT, '--scoped', '--key-stdin', '--no-sync-history'], h.deps);

    const said = h.output();
    expect(said).toContain(`Attached to ${ENDPOINT} as a personal device.`);
    expect(said).toContain(
      'Activity is sent to that deployment only from repositories you enroll, and',
    );
    expect(said).not.toContain('Only activity');
    expect(said).toContain(
      'Nothing is enrolled yet. Run `aka enroll` in a repository to start sending it.',
    );
    expect(said).not.toContain('Everything else this machine records');
    expect(said).toContain(
      'anywhere else stays on this machine. A command you run inside an enrolled',
    );
    expect(said).toContain(
      "repository is sent as that repository's activity, even when it reads files",
    );
    expect(flat(said)).toContain(REPORT_SENTENCE("that deployment's"));
    for (const phrase of REPORT_OLD_PHRASES) expect(said).not.toContain(phrase);
    expect(said).toContain(
      'An aka older than this one that re-attaches this machine makes it machine-wide.',
    );
    expect(said).not.toContain('Activity from here on is sent to that deployment automatically.');
  });

  it('says exactly this on a personal device, so a sentence added later has to be added here', async () => {
    const h = harness({ interactive: false, stdin: KEY_1 });

    await runAttach(['--url', ENDPOINT, '--scoped', '--key-stdin', '--no-sync-history'], h.deps);

    expect(h.output()).toBe(
      [
        `Attached to ${ENDPOINT} as a personal device.`,
        '  organization  Example Org',
        '  you           member-17',
        '',
        'Activity is sent to that deployment only from repositories you enroll, and',
        'the Data Shares register a scan records goes only for an enrolled',
        'repository — destinations and call sites, never source text. Activity',
        'anywhere else stays on this machine. A command you run inside an enrolled',
        "repository is sent as that repository's activity, even when it reads files",
        'elsewhere.',
        'Nothing is enrolled yet. Run `aka enroll` in a repository to start sending it.',
        '',
        'Whenever a session starts anywhere on this machine, in a repository or not',
        "(a browser chat included), the machine pulls that deployment's policy (at",
        'most every 15 minutes) and sends it a device report (at most hourly): a',
        'device identifier, host name, versions, detection packs, policy counts, and',
        'finding counts and dates for everything recorded on the machine. Where a',
        'scan is available (the coding-agent plugins, not a browser chat), the same',
        'session start also checks it for device commands.',
        'An aka older than this one that re-attaches this machine makes it machine-wide.',
        '',
        'Policy arrives on the next session. Run `aka status` to see it.',
        '',
      ].join('\n'),
    );
  });

  it('prints nothing from the deployment or the label that could repaint a terminal', async () => {
    // Control characters in what whoami returned must not reach the terminal.
    const ESC = String.fromCharCode(27);
    const who = { tenantName: `Example${ESC}[31m Org`, userEmail: `member${ESC}[2J-17` };
    const h = harness({ interactive: true, answers: [KEY_1, 'n'], who });

    await runAttach(['--url', ENDPOINT, '--scoped'], h.deps);

    expect(exits).toEqual([]);
    expect(h.output()).not.toContain(ESC);
    expect(h.output()).toContain('Verified against Example[31m Org.');
    expect(h.output()).toContain('  organization  Example[31m Org');
    expect(h.output()).toContain('  you           member[2J-17');
  });

  it('shows an organization and an account as long as the schema allows, whole', async () => {
    // The strip bounds a value, and the bound has to be the schema's: a name of
    // 200 characters and an address of 320 are valid and would be cut at 80.
    const who = { tenantName: 'o'.repeat(150), userEmail: `${'u'.repeat(150)}@example.com` };
    const h = harness({ interactive: true, answers: [KEY_1, 'n'], who });

    await runAttach(['--url', ENDPOINT, '--scoped'], h.deps);

    expect(exits).toEqual([]);
    expect(h.output()).toContain(`Verified against ${who.tenantName}.`);
    expect(h.output()).toContain(`  organization  ${who.tenantName}\n`);
    expect(h.output()).toContain(`  you           ${who.userEmail}\n`);
  });

  it('leaves the machine-wide text as it was', async () => {
    const h = harness({ interactive: false, stdin: KEY_1 });

    await runAttach(['--url', ENDPOINT, '--machine', '--key-stdin', '--no-sync-history'], h.deps);

    const said = h.output();
    expect(said).toContain('Activity from here on is sent to that deployment automatically.');
    expect(said).toContain(
      'So is the Data Shares register a scan records — destinations and call sites, never source text.',
    );
    expect(said).not.toContain('personal device');
  });

  it('asks a personal device about history without counting the machine', async () => {
    stand.preview = { sessions: 40, days: 12 };
    const h = harness({ interactive: true, answers: [KEY_1, 'y'] });

    await runAttach(['--url', ENDPOINT, '--scoped'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([ACCESS_KEY, SCOPED_HISTORY]);
    expect(stand.previewReads).toBe(0);
    const said = h.output();
    expect(said).toContain(
      'This machine is attaching as a personal device: AKA sends the activity of',
    );
    // The caveat the success text keeps is kept here too.
    expect(said).toContain('activity, even when it reads files elsewhere.');
    expect(said).not.toContain('12 days');
    expect(said).not.toContain('40 sessions');
    expect(said).toContain(
      'Unsent activity from the repositories you enroll is sent in the background,',
    );
    expect(storedSettings().historySyncConsent).toMatchObject({ endpoint: ENDPOINT });
  });

  it('asks the scoped history question when the personal-device answer chose the mode', async () => {
    // No --scoped here: the mode comes from the answer, so the history question
    // has to be given the settled mode and not the flag.
    stand.preview = { sessions: 40, days: 12 };
    const h = harness({ interactive: true, answers: [KEY_1, 'y', 'y'] });

    await runAttach(['--url', ENDPOINT], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([ACCESS_KEY, PERSONAL_DEVICE, SCOPED_HISTORY]);
    expect(stand.previewReads).toBe(0);
    expect(modeOnDisk()).toBe('scoped');
    expect(h.output()).not.toContain('12 days');
    expect(storedSettings().historySyncConsent).toMatchObject({ endpoint: ENDPOINT });
  });

  it('asks the machine-wide history question when the personal-device answer is no', async () => {
    stand.preview = { sessions: 40, days: 12 };
    const h = harness({ interactive: true, answers: [KEY_1, 'n', 'n'] });

    await runAttach(['--url', ENDPOINT], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([ACCESS_KEY, PERSONAL_DEVICE, MACHINE_HISTORY]);
    expect(stand.previewReads).toBe(1);
    expect(modeOnDisk()).toBe('machine');
  });

  it('says it did not ask about history on a personal device with no terminal', async () => {
    stand.preview = { sessions: 40, days: 12 };
    const h = harness({ interactive: false, stdin: KEY_1 });

    await runAttach(['--url', ENDPOINT, '--scoped', '--key-stdin'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([]);
    expect(stand.previewReads).toBe(0);
    expect(h.errors()).toContain('Not asking about existing history: no terminal to prompt on.');
    expect(storedSettings()).not.toHaveProperty('historySyncConsent');
  });

  it('still counts the machine before a machine-wide history grant', async () => {
    stand.preview = { sessions: 40, days: 12 };
    const h = harness({ interactive: true, answers: [KEY_1, 'n'] });

    await runAttach(['--url', ENDPOINT, '--machine'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([ACCESS_KEY, MACHINE_HISTORY]);
    expect(stand.previewReads).toBe(1);
    expect(h.output()).toContain(
      'This machine has 12 days of activity already recorded locally (40 sessions).',
    );
  });
});

// Strings someone else wrote reach the terminal only through the strip: the name
// an administrator gives their organization, the endpoint they pin, and the
// address or option the user typed. None of them is checked for control
// characters when it is read, so an escape sequence in one must not repaint the
// lines around it.
describe('what an attach prints of strings it did not write', () => {
  const ESC = String.fromCharCode(27);
  const EVIL_ORG = `Example${ESC}[2J IT`;
  const SHOWN_ORG = 'Example[2J IT';
  const EVIL_ENDPOINT = `${OTHER_ENDPOINT}/gateway${ESC}[2J`;
  const SHOWN_ENDPOINT = `${OTHER_ENDPOINT}/gateway[2J`;
  const TYPED = `${ENDPOINT}/gateway${ESC}[2J`;
  const SHOWN_TYPED = `${ENDPOINT}/gateway[2J`;

  const governed = (organization = EVIL_ORG): ManagedSettings =>
    ManagedSettings.parse({ organization, values: { controlPlane: { endpoint: ENDPOINT } } });

  it('strips the organization from the refusal of --scoped', async () => {
    const overlay = governed();
    const h = harness({ interactive: true, managed: () => overlay });

    await runAttach(['--url', ENDPOINT, '--scoped'], h.deps);

    expect(exits).toEqual([2]);
    expect(h.errors()).toContain(
      `${connectionRefusalMessage({ reason: 'scoped-managed', organization: SHOWN_ORG })} ` +
        'Re-run without --scoped.',
    );
    expect(h.errors()).not.toContain(ESC);
  });

  it('strips the organization from the line that says a managed attach widens a personal device', async () => {
    attachedScoped(BOUND);
    const overlay = governed();
    const h = harness({ interactive: false, stdin: KEY_2, managed: () => overlay });

    await runAttach(['--url', ENDPOINT, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.output()).toContain(
      `${connectionRefusalMessage({ reason: 'scoped-managed', organization: SHOWN_ORG })} ` +
        `This machine was attached to ${ENDPOINT} as a personal device; ` +
        'its enrolled list will be cleared.',
    );
    expect(h.output()).not.toContain(ESC);
  });

  it('strips the organization from the refusal of a scoped write that became managed while it waited', async () => {
    let overlay: ManagedSettings | null = null;
    const h = harness({
      interactive: false,
      stdin: KEY_1,
      managed: () => overlay,
      duringVerify: () => {
        overlay = governed();
      },
    });

    await runAttach(['--url', ENDPOINT, '--scoped', '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.errors()).toContain(
      `${connectionRefusalMessage({ reason: 'scoped-managed', organization: SHOWN_ORG })} ` +
        'Nothing was changed on this machine.',
    );
    expect(h.errors()).not.toContain(ESC);
  });

  it('strips the organization and the pinned endpoint from the refusal of another deployment', async () => {
    const overlay = ManagedSettings.parse({
      organization: EVIL_ORG,
      values: { controlPlane: { endpoint: EVIL_ENDPOINT } },
    });
    const h = harness({ interactive: true, managed: () => overlay });

    await runAttach(['--url', ENDPOINT], h.deps);

    expect(exits).toEqual([2]);
    expect(h.errors()).toContain(
      connectionRefusalMessage({
        reason: 'pinned-endpoint',
        organization: SHOWN_ORG,
        endpoint: SHOWN_ENDPOINT,
      }),
    );
    expect(h.errors()).not.toContain(ESC);
  });

  it('strips the organization from the refusal of an attach that would drop the name', async () => {
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, label: 'Old', attachedAt: ISO } },
      base,
      null,
    );
    const overlay = ManagedSettings.parse({ organization: EVIL_ORG, lockedFields: ['runMode'] });
    const h = harness({ interactive: false, stdin: KEY_1, managed: () => overlay });

    await runAttach(['--url', ENDPOINT, '--key-stdin'], h.deps);

    expect(exits).toEqual([2]);
    expect(h.errors()).toContain(
      `${connectionRefusalMessage({ reason: 'label-required', organization: SHOWN_ORG })} ` +
        'Attach with the --label it already has, as `aka status` shows it.',
    );
    expect(h.errors()).not.toContain(ESC);
  });

  it('strips the organization and the endpoint from the refusal of a detach', () => {
    const overlay = ManagedSettings.parse({
      organization: EVIL_ORG,
      values: { runMode: 'attached', controlPlane: { endpoint: EVIL_ENDPOINT } },
    });
    const h = harness({ interactive: false, managed: () => overlay });

    runDetach([], h.deps);

    expect(exits).toEqual([1]);
    expect(h.errors()).toContain(
      connectionRefusalMessage({
        reason: 'held-attached',
        organization: SHOWN_ORG,
        endpoint: SHOWN_ENDPOINT,
      }),
    );
    expect(h.errors()).not.toContain(ESC);
  });

  it('shows an organization as long as the strip allows, whole', async () => {
    const organization = 'o'.repeat(150);
    const overlay = governed(organization);
    const h = harness({ interactive: true, managed: () => overlay });

    await runAttach(['--url', ENDPOINT, '--scoped'], h.deps);

    expect(h.errors()).toContain(`${organization} manages this machine`);
  });

  it('strips the typed address from the confirmation of a widening', async () => {
    attachedScoped({ ...BOUND, endpoint: TYPED }, TYPED);
    const h = harness({ interactive: true, answers: [KEY_2, 'y'] });

    await runAttach(['--url', TYPED, '--machine', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.asked).toEqual([ACCESS_KEY, WIDEN]);
    expect(h.output()).toContain(
      `This machine is attached to ${SHOWN_TYPED} as a personal device: activity is`,
    );
    expect(h.output()).not.toContain(ESC);
  });

  it('strips the typed address from the line that says a widening is going ahead', async () => {
    attachedScoped({ ...BOUND, endpoint: TYPED }, TYPED);
    const h = harness({ interactive: false, stdin: KEY_2 });

    await runAttach(['--url', TYPED, '--machine', '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([]);
    expect(h.output()).toContain(
      `Attaching machine-wide, as --machine asks. This machine was attached to ${SHOWN_TYPED} ` +
        'as a personal device; its enrolled list will be cleared.',
    );
    expect(h.output()).not.toContain(ESC);
  });

  it('strips the typed address from the refusal of a key the deployment does not accept', async () => {
    const h = harness({ interactive: false, stdin: KEY_1, who: null });

    await runAttach(['--url', TYPED, '--key-stdin', '--no-sync-history'], h.deps);

    expect(exits).toEqual([1]);
    expect(h.errors()).toContain(`could not verify that key against ${SHOWN_TYPED}.`);
    expect(h.errors()).not.toContain(ESC);
  });

  it('strips an option it does not know from the usage error', () => {
    expect(parseAttachArgs([`--bogus${ESC}[2J`])).toEqual({ error: 'unknown option --bogus[2J' });
  });

  it('strips the settings directory from the report that it cannot be read', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('a control character cannot be part of a Windows path');
      return;
    }
    const odd = join(base, `home${ESC}[2J`);
    mkdirSync(odd);
    writeFileSync(settingsDirOf(odd), 'not a directory');
    const h = harness({ interactive: true });

    await runAttach(['--url', ENDPOINT], { ...h.deps, base: odd });

    expect(exits).toEqual([1]);
    expect(h.errors()).toContain('home[2J');
    expect(h.errors()).not.toContain(ESC);
  });
});
