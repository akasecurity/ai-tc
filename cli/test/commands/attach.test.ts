import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  controlPlaneCredentialPath,
  dataDir as dataDirOf,
  openLocalDatabase,
  readWorkspaceSettings,
  settingsDir as settingsDirOf,
} from '@akasecurity/persistence';
import type { ManagedSettings } from '@akasecurity/schema';
import { HISTORY_SYNC_PAYLOAD_VERSION, isHistorySyncConsentValid } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { parseAttachArgs, runAttach, runDetach, runStatus } from '../../src/commands/attach.ts';
import type { Prompter } from '../../src/lib/prompter.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

/**
 * Scripted Prompter with stdout and stderr kept APART.
 *
 * The two are separate here, unlike the sibling suites' single buffer, because
 * this command's assertions are about which channel a message reached: a
 * refusal that lands on stdout is a refusal a script pipes into its next
 * command, and a success line on stderr is one a human reads as an error.
 */
function scriptedPrompter(opts: {
  interactive: boolean;
  answers?: string[];
  stdin?: string;
}): Prompter & { output: () => string; errors: () => string } {
  const out: string[] = [];
  const err: string[] = [];
  const answers = [...(opts.answers ?? [])];
  const next = (): Promise<string> => {
    const answer = answers.shift();
    // An unscripted question rejects rather than hanging, so a prompt this
    // suite did not expect fails loudly instead of timing the run out.
    return answer === undefined
      ? Promise.reject(new Error('unscripted prompt'))
      : Promise.resolve(answer);
  };
  return {
    output: () => out.join(''),
    errors: () => err.join(''),
    out: (text) => {
      out.push(text);
    },
    err: (text) => {
      err.push(text);
    },
    isInteractive: opts.interactive,
    ask: next,
    askHidden: next,
    readAllStdin: () => Promise.resolve(opts.stdin ?? ''),
  };
}

// The attach UX, and the one rule it exists to hold: the key reaches the disk
// without ever reaching argv, a log, or the terminal.

// High-entropy and deliberately NOT credential-shaped — this tree is public, so
// a fixture that looks like a real key does not belong in it. What the window
// in `expectNoEchoOf` needs is entropy, not plausibility.
const KEY = 'not-a-real-key-8c4e1a7f2b95';
const ENDPOINT = 'https://aka.example-org.internal';

let base: string;
let exits: number[];

const verify = () => Promise.resolve({ tenantName: 'Example Org', userEmail: 'dev@example.com' });

/**
 * A deployment that does not offer browser approval.
 *
 * Every case in this file is about the KEY path — the prompt, the write, the
 * rollback — and `aka attach` now tries the interactive path first. Stubbing it
 * as not-offered is what a pre-device-flow deployment does, so these cases
 * exercise the same fall-through a real one produces rather than reaching for
 * a socket the no-network guard would refuse.
 *
 * The interactive path has its own suite (attach-device.test.ts), and the
 * PREFERENCE between the two is asserted below rather than assumed here.
 */
const notOffered = () => Promise.resolve({ kind: 'not-offered' as const });

const deps = (io: ReturnType<typeof scriptedPrompter>) => ({
  base,
  prompter: io,
  verify,
  deviceAttach: notOffered,
  // UNMANAGED, stated rather than inherited. The administrative overlay lives
  // at absolute system paths that a temp home cannot redirect, so without this
  // every case here reads whatever the machine running it is enrolled in — and
  // a developer whose own laptop is managed sees six unrelated failures.
  managedSettings: null,
  // Stubbed rather than left to the real default: the real one writes an
  // actual LaunchAgent plist and shells out to launchctl on a real macOS
  // runner, which is not a side effect any case in this file should have.
  // Its own behaviour is covered by @akasecurity/local-ops's
  // background-schedule suite.
  installBackgroundSync: () => undefined,
  uninstallBackgroundSync: () => undefined,
  exit: (code: number) => exits.push(code),
});

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-attach-'));
  exits = [];
});

afterEach(() => {
  removeTree(base);
});

describe('the key never travels in argv', () => {
  it('refuses --key by name, and says where the key goes instead', () => {
    const result = parseAttachArgs(['--url', ENDPOINT, '--key', KEY]);
    expect('error' in result && result.error).toContain('--key-stdin');
    // Named explicitly rather than falling into the generic unknown-flag
    // message: someone reaching for it is trying to do the one thing this
    // command must not allow.
    expect('error' in result && result.error).toContain('shell history');
  });

  it('refuses --key=… too', () => {
    expect('error' in parseAttachArgs([`--key=${KEY}`])).toBe(true);
  });

  it('exits 2 on an unknown flag rather than ignoring it', async () => {
    // A mistyped flag that is silently dropped is how a key ends up somewhere
    // nobody looked.
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT, '--kee-stdin'], deps(io));
    expect(exits).toEqual([2]);
  });

  it('never echoes the key it was given', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT, '--no-sync-history'], deps(io));
    // Positive control first: the command really did say something on success,
    // so the absence assertions below cannot pass on an empty string.
    expect(io.output()).toContain('Attached to');
    expectNoEchoOf(io.output(), KEY);
    expectNoEchoOf(io.errors(), KEY);
  });
});

describe('what attach writes', () => {
  it('stores the credential beside settings, and never in settings', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(
      ['--url', ENDPOINT, '--label', 'Example Org production', '--no-sync-history'],
      deps(io),
    );

    const credential: unknown = JSON.parse(
      readFileSync(controlPlaneCredentialPath(settingsDirOf(base)), 'utf8'),
    );
    expect(credential).toMatchObject({ endpoint: ENDPOINT, apiKey: KEY });

    const settings = readWorkspaceSettings(base);
    expect(settings.runMode).toBe('attached');
    expect(settings.controlPlane).toMatchObject({
      endpoint: ENDPOINT,
      label: 'Example Org production',
    });
    // settings.json is rendered by the dashboard and pinned by administrators;
    // the key must not be in it.
    expectNoEchoOf(readFileSync(join(settingsDirOf(base), 'settings.json'), 'utf8'), KEY);
  });

  it('takes the key from stdin when asked, for an unattended enrolment', async () => {
    const io = scriptedPrompter({ interactive: false, stdin: `${KEY}\n` });
    await runAttach(['--url', ENDPOINT, '--key-stdin'], deps(io));
    expect(exits).toEqual([]);
    const credential: unknown = JSON.parse(
      readFileSync(controlPlaneCredentialPath(settingsDirOf(base)), 'utf8'),
    );
    expect(credential).toMatchObject({ apiKey: KEY });
  });
});

describe('what attach refuses', () => {
  /**
   * A label is printed into `aka status`, which is the block a user reads to
   * decide whether their machine is managed. An escape sequence in it can
   * repaint that block or hide a line — and unlike the endpoint, nothing about
   * a label's shape is otherwise constrained.
   *
   * REFUSED here rather than stripped, because the person who typed it can fix
   * it. The renderer strips instead, since a label can also arrive from an
   * administrator's managed overlay that the reader cannot correct; both layers
   * are tested, in their own packages, and neither substitutes for the other.
   */
  it('a --label carrying an escape sequence, since status renders it', () => {
    const result = parseAttachArgs(['--url', ENDPOINT, '--label', 'Acme\u001b[2K\u001b[A']);
    expect('error' in result && result.error).toContain('control characters');
    // Names the consequence, not just the rule: the reader has to know why a
    // label they typed is being turned down.
    expect('error' in result && result.error).toContain('aka status');
  });

  it('a --label carrying a zero-width character, not only an escape', () => {
    // \p{Cf} as well as \p{Cc}: a zero-width joiner cannot repaint a terminal
    // but can make two different deployments render identically, which is the
    // same deception one layer down.
    const result = parseAttachArgs(['--url', ENDPOINT, '--label', 'Acme\u200bProd']);
    expect('error' in result && result.error).toContain('control characters');
  });

  it('but accepts an ordinary label, so the refusal is not a ban on labels', () => {
    const result = parseAttachArgs(['--url', ENDPOINT, '--label', 'Acme Prod (eu-west)']);
    expect('error' in result).toBe(false);
    expect('label' in result && result.label).toBe('Acme Prod (eu-west)');
  });

  it('a plaintext endpoint, before the key is ever put on a wire', async () => {
    let verified = false;
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', 'http://aka.example-org.internal'], {
      ...deps(io),
      verify: () => {
        verified = true;
        return verify();
      },
    });

    expect(exits).toEqual([2]);
    expect(verified).toBe(false);
    expect(io.errors()).toContain('in the clear');
  });

  it('an endpoint carrying a password, before the key is ever put on a wire', async () => {
    let verified = false;
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', 'https://svc:SUPER-SECRET-PASSWORD@aka.example-org.internal'], {
      ...deps(io),
      verify: () => {
        verified = true;
        return verify();
      },
    });

    expect(exits).toEqual([2]);
    expect(verified).toBe(false);
    // Positive control: the origin still reaches the message, and the refusal
    // names the userinfo cause — this is not merely "the message is empty".
    expect(io.errors()).toContain('https://aka.example-org.internal');
    expect(io.errors()).toContain('username or password');
    expectNoEchoOf(io.errors(), 'SUPER-SECRET-PASSWORD');
  });

  it('a key the deployment does not accept, and writes nothing', async () => {
    // What verification buys: the difference between "attached" and "attached
    // to something that will refuse every request from now on" — which would
    // otherwise be silent, because every later failure is swallowed by design.
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT], {
      ...deps(io),
      verify: () => Promise.reject(new Error('401')),
    });

    expect(exits).toEqual([1]);
    expect(readWorkspaceSettings(base).runMode).toBe('standalone');
    expect(() => readFileSync(controlPlaneCredentialPath(settingsDirOf(base)), 'utf8')).toThrow();
  });

  it('an empty key', async () => {
    const io = scriptedPrompter({ interactive: true, answers: ['   '] });
    await runAttach(['--url', ENDPOINT], deps(io));
    expect(exits).toEqual([2]);
  });
});

describe('the --home flag every other command honours', () => {
  it('attach, detach and status all target the home they are given', async () => {
    // These three read the real ~/.aka regardless of argv until now, and on
    // detach that is the sharp one: `aka detach --home /tmp/scratch` would have
    // cleared the user's ACTUAL machine while appearing to touch a throwaway.
    // `deps.base` is not passed here on purpose — the flag has to be what
    // resolves the home.
    // `base` is omitted on purpose — the FLAG has to be what resolves the home,
    // which is the whole point of the case. The other two seams are still
    // supplied, and both are load-bearing rather than tidiness:
    //
    //   `deviceAttach` — without it the real browser-approval probe runs and
    //   opens a socket to ENDPOINT. That is a live network call from a unit
    //   test: the no-network guard fails the run for it, and correctly, since
    //   the probe's own catch then swallows the refusal. This case is about the
    //   --home flag and has no business exercising the device flow at all.
    //
    //   `managedSettings` — the administrative overlay lives at absolute system
    //   paths a temp home cannot redirect, so without it this reads whatever the
    //   machine is enrolled in. On a managed laptop that pins `runMode:
    //   attached`, which makes the FIRST assertion below pass no matter what
    //   attach wrote — an assertion passing for the wrong reason, which is
    //   worse than one failing.
    const stubbed = {
      deviceAttach: notOffered,
      managedSettings: null,
      // See the shared deps() helper above for why these are stubbed rather
      // than left to the real default.
      installBackgroundSync: () => undefined,
      uninstallBackgroundSync: () => undefined,
      exit: () => undefined,
    };

    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT, '--home', base, '--no-sync-history'], {
      ...stubbed,
      prompter: io,
      verify,
    });
    expect(readWorkspaceSettings(base).runMode).toBe('attached');

    const out = scriptedPrompter({ interactive: true });
    await runStatus(['--home', base], { ...stubbed, prompter: out });
    expect(out.output()).toContain(ENDPOINT);

    const off = scriptedPrompter({ interactive: true });
    runDetach(['--home', base], { ...stubbed, prompter: off });
    expect(readWorkspaceSettings(base).runMode).toBe('standalone');
  });

  it('detach and status refuse an unknown flag rather than ignoring it', () => {
    const io = scriptedPrompter({ interactive: true });
    runDetach(['--hoem', base], deps(io));
    expect(exits).toEqual([2]);
    // …and nothing was cleared on the way to refusing.
    expect(io.output()).toBe('');
  });
});

describe('output', () => {
  it('ends every verb with a newline, like every other command', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT, '--no-sync-history'], deps(io));
    expect(io.output().endsWith('\n')).toBe(true);

    const st = scriptedPrompter({ interactive: true });
    await runStatus([], deps(st));
    expect(st.output().endsWith('\n')).toBe(true);

    const off = scriptedPrompter({ interactive: true });
    runDetach([], deps(off));
    expect(off.output().endsWith('\n')).toBe(true);
  });
});

describe('detach', () => {
  it('clears both halves and everything derived from them', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT, '--no-sync-history'], deps(io));

    // The cached bundle and the recorded outcome, as the sync child leaves them.
    const dataDir = dataDirOf(base);
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(join(dataDir, 'policy-cache.json'), '{}', { mode: 0o600 });
    writeFileSync(join(dataDir, 'attached-sync-state.json'), '{}', { mode: 0o600 });

    const out = scriptedPrompter({ interactive: true });
    runDetach([], { ...deps(out) });

    expect(readWorkspaceSettings(base).runMode).toBe('standalone');
    expect(readWorkspaceSettings(base).controlPlane).toBeUndefined();
    expect(() => readFileSync(controlPlaneCredentialPath(settingsDirOf(base)), 'utf8')).toThrow();
    // The cached policy is the one that MUST go: it merges raise-only, so one
    // left behind keeps escalating enforcement on a machine nothing manages,
    // and nothing would ever refresh or clear it.
    expect(() => readFileSync(join(dataDir, 'policy-cache.json'), 'utf8')).toThrow();
    expect(() => readFileSync(join(dataDir, 'attached-sync-state.json'), 'utf8')).toThrow();
    expect(out.output()).toContain('Detached');
  });

  it('says so plainly when there was nothing to detach', () => {
    const io = scriptedPrompter({ interactive: true });
    runDetach([], deps(io));
    expect(io.output()).toContain('was not attached');
    expect(exits).toEqual([]);
  });

  it('passes the RESOLVED --home to uninstallBackgroundSync, never the real default', () => {
    // Regression: `uninstallBackgroundSync` used to be called with no
    // arguments at all, so it fell back to the real home unconditionally —
    // `aka detach --home /tmp/scratch` on a machine already attached against
    // the real ~/.aka would boot out and delete the LaunchAgent belonging to
    // the user's ACTUAL machine while reporting it touched a throwaway.
    // `deps.base` is deliberately omitted, as in the `--home` suite above —
    // the FLAG has to be what resolves it.
    const seen: string[] = [];
    const io = scriptedPrompter({ interactive: true });
    runDetach(['--home', base], {
      deviceAttach: notOffered,
      managedSettings: null,
      installBackgroundSync: () => undefined,
      uninstallBackgroundSync: (b: string) => {
        seen.push(b);
      },
      prompter: io,
      exit: (code: number) => exits.push(code),
    });
    expect(seen).toEqual([base]);
  });

  it('passes the RESOLVED --home to installBackgroundSync on attach, the same way', async () => {
    const seen: string[] = [];
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT, '--home', base, '--no-sync-history'], {
      deviceAttach: notOffered,
      managedSettings: null,
      verify,
      installBackgroundSync: (b: string) => {
        seen.push(b);
      },
      uninstallBackgroundSync: () => undefined,
      prompter: io,
      exit: (code: number) => exits.push(code),
    });
    expect(seen).toEqual([base]);
  });
});

/**
 * A pinned overlay with NO lock — the shape a fleet kit ships, so that no save
 * of the user's is ever refused by the writer. The writer indeed refuses
 * nothing, and that was the defect: `aka detach` cleared the user's file and
 * printed "Detached.", and `aka attach --url <other>` stored a credential for
 * another deployment — while every later read overlaid the pin straight back,
 * leaving a machine that reads attached to the pinned deployment holding a
 * credential that is not for it, or none at all. Both verbs now decide against
 * what the machine will READ, not against what the writer would take.
 *
 * `readWorkspaceSettings(base)` below is the user's OWN file: the overlay under
 * test reaches the verbs through `managedSettings` only, and the process-wide
 * guard in test/setup/no-managed-settings.ts reads no administrator's file.
 */
describe('a pinned overlay with no lock, as a fleet kit ships it', () => {
  const PINNED = 'https://pinned.example-org.internal';
  const OTHER = 'https://other.example-org.internal';
  const overlay: ManagedSettings = {
    specVersion: 1,
    organization: 'Example Org',
    values: { runMode: 'attached', controlPlane: { endpoint: PINNED, label: 'example-prod' } },
    lockedFields: [],
  };
  const pinnedDeps = (io: ReturnType<typeof scriptedPrompter>) => ({
    ...deps(io),
    managedSettings: overlay,
  });
  const credential = (): unknown => {
    const parsed: unknown = JSON.parse(
      readFileSync(controlPlaneCredentialPath(settingsDirOf(base)), 'utf8'),
    );
    return parsed;
  };
  const boundaryFrozen = (): boolean => {
    const db = openLocalDatabase(dataDirOf(base));
    try {
      return db.historySync.deployment().backlogBefore !== undefined;
    } finally {
      db.close();
    }
  };
  const freezeBoundary = (): void => {
    const db = openLocalDatabase(dataDirOf(base));
    try {
      db.historySync.rearmFor('some-fingerprint', Date.parse('2026-08-01T00:00:00.000Z'));
    } finally {
      db.close();
    }
  };

  it('still attaches to the pinned endpoint — that is the enrolment path', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', PINNED, '--no-sync-history'], pinnedDeps(io));
    expect(exits).toEqual([]);
    expect(io.output()).toContain('Attached to');
    expect(credential()).toMatchObject({ endpoint: PINNED });
    // Nothing is asserted about the user's own file here: what of a pinned
    // connection the writer persists is the writer's decision, pinned by the
    // persistence suite — an exact echo of the pin is stripped, not stored.
  });

  it('refuses to attach elsewhere, naming who pinned it and to what, before any key is sent', async () => {
    let verified = false;
    let granted = false;
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', OTHER, '--no-sync-history'], {
      ...pinnedDeps(io),
      verify: () => {
        verified = true;
        return verify();
      },
      deviceAttach: () => {
        granted = true;
        return notOffered();
      },
    });
    expect(exits).toEqual([2]);
    expect(verified).toBe(false);
    expect(granted).toBe(false);
    // A decision the user can act on: whose, and to where.
    expect(io.errors()).toContain('Example Org');
    expect(io.errors()).toContain(PINNED);
    expect(io.output()).toBe('');
    // Nothing was written: no credential, and the user's own file untouched.
    expect(() => credential()).toThrow();
    expect(readWorkspaceSettings(base).runMode).toBe('standalone');
  });

  it('refuses the unattended key path too, and never reaches the wire', async () => {
    // The pre-flight used to run only ahead of the browser flow, so
    // `--key-stdin` sailed past it to the write — which under a pin lands.
    let verified = false;
    const io = scriptedPrompter({ interactive: false, stdin: `${KEY}\n` });
    await runAttach(['--url', OTHER, '--key-stdin'], {
      ...pinnedDeps(io),
      verify: () => {
        verified = true;
        return verify();
      },
    });
    expect(exits).toEqual([2]);
    expect(verified).toBe(false);
    expect(io.errors()).toContain(PINNED);
    expectNoEchoOf(io.errors(), KEY);
    expect(() => credential()).toThrow();
  });

  it('refuses to detach, naming who pinned it and to what, and leaves both halves in place', async () => {
    await runAttach(
      ['--url', PINNED, '--no-sync-history'],
      pinnedDeps(scriptedPrompter({ interactive: true, answers: [KEY] })),
    );
    const before = readWorkspaceSettings(base);

    const off = scriptedPrompter({ interactive: true });
    runDetach([], pinnedDeps(off));
    expect(exits).toEqual([1]);
    expect(off.errors()).toContain('Example Org');
    expect(off.errors()).toContain(PINNED);
    // Not "Detached." — the line this refusal replaces.
    expect(off.output()).toBe('');
    expect(credential()).toMatchObject({ endpoint: PINNED });
    expect(readWorkspaceSettings(base)).toEqual(before);
  });

  it('refuses to detach a machine that never attached, since the pin is what it reads', () => {
    // No credential, nothing in the user's file — and every read still reports
    // the machine attached to the pin. "Nothing to do" would be true of the
    // file and false of the machine.
    const off = scriptedPrompter({ interactive: true });
    runDetach([], pinnedDeps(off));
    expect(exits).toEqual([1]);
    expect(off.errors()).toContain(PINNED);
    expect(off.output()).toBe('');
  });

  it('refuses before the history boundary is released, so a refused detach changes nothing', async () => {
    await runAttach(
      ['--url', PINNED, '--sync-history'],
      pinnedDeps(scriptedPrompter({ interactive: true, answers: [KEY] })),
    );
    freezeBoundary();
    expect(boundaryFrozen()).toBe(true);

    runDetach([], pinnedDeps(scriptedPrompter({ interactive: true })));
    expect(exits).toEqual([1]);
    expect(boundaryFrozen()).toBe(true);
  });

  it('a lock with no pin is refused the same way, ahead of the write', async () => {
    // The lock already refused, but from the writer — AFTER the history window
    // had been closed for a detach that then did not happen. Attached
    // unmanaged first, because a lock with no value freezes whatever the user
    // last chose.
    const locked: ManagedSettings = {
      specVersion: 1,
      organization: 'Example Org',
      values: {},
      lockedFields: ['runMode'],
    };
    await runAttach(
      ['--url', ENDPOINT, '--sync-history'],
      deps(scriptedPrompter({ interactive: true, answers: [KEY] })),
    );
    freezeBoundary();

    const off = scriptedPrompter({ interactive: true });
    runDetach([], { ...deps(off), managedSettings: locked });
    expect(exits).toEqual([1]);
    expect(off.errors()).toContain('Example Org');
    expect(off.errors()).toContain(ENDPOINT);
    expect(off.output()).toBe('');
    expect(readWorkspaceSettings(base).runMode).toBe('attached');
    expect(boundaryFrozen()).toBe(true);
  });

  it('a pin on the descriptor alone leaves the mode the user’s, so a detach still lands', async () => {
    // The refusal is about what the next read will UNDO. With `runMode`
    // neither pinned nor locked, a cleared file reads back as standalone —
    // the dangling pinned descriptor is not an attachment without the mode —
    // so this detach takes effect and is the user's to make.
    const planeOnly: ManagedSettings = {
      specVersion: 1,
      organization: 'Example Org',
      values: { controlPlane: { endpoint: PINNED, label: 'example-prod' } },
      lockedFields: [],
    };
    await runAttach(['--url', PINNED, '--no-sync-history'], {
      ...deps(scriptedPrompter({ interactive: true, answers: [KEY] })),
      managedSettings: planeOnly,
    });
    expect(readWorkspaceSettings(base).runMode).toBe('attached');

    const off = scriptedPrompter({ interactive: true });
    runDetach([], { ...deps(off), managedSettings: planeOnly });
    expect(exits).toEqual([]);
    expect(off.output()).toContain('Detached');
    expect(readWorkspaceSettings(base).runMode).toBe('standalone');
  });

  it.each<[string, ManagedSettings]>([
    [
      'pinned',
      {
        specVersion: 1,
        organization: 'Example Org',
        values: { runMode: 'standalone' },
        lockedFields: [],
      },
    ],
    [
      'locked',
      { specVersion: 1, organization: 'Example Org', values: {}, lockedFields: ['runMode'] },
    ],
  ])(
    'refuses an attach on a machine whose mode is %s to standalone, before any key is sent',
    async (_how, standalone) => {
      // Either way the attach would be written and then read back as
      // standalone, so it is refused where nobody has been sent anywhere yet.
      let verified = false;
      let granted = false;
      const io = scriptedPrompter({ interactive: true, answers: [KEY] });
      await runAttach(['--url', PINNED, '--no-sync-history'], {
        ...deps(io),
        managedSettings: standalone,
        verify: () => {
          verified = true;
          return verify();
        },
        deviceAttach: () => {
          granted = true;
          return notOffered();
        },
      });
      expect(exits).toEqual([2]);
      expect(verified).toBe(false);
      expect(granted).toBe(false);
      expect(io.errors()).toContain(
        'Example Org manages this machine and has set it to standalone, so it cannot be attached here.',
      );
      expect(io.output()).toBe('');
      expect(() => credential()).toThrow();
    },
  );

  it('refuses a --label that differs from the pinned one, before any key is sent', async () => {
    // A label-only difference is still a change to the pinned descriptor, and
    // the next read would overlay the administrator's label straight back.
    let verified = false;
    let granted = false;
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', PINNED, '--label', 'renamed-here', '--no-sync-history'], {
      ...pinnedDeps(io),
      verify: () => {
        verified = true;
        return verify();
      },
      deviceAttach: () => {
        granted = true;
        return notOffered();
      },
    });
    expect(exits).toEqual([2]);
    expect(verified).toBe(false);
    expect(granted).toBe(false);
    expect(io.errors()).toContain(
      'Example Org manages this machine name, so it cannot be renamed here.',
    );
    expect(io.output()).toBe('');
    expect(() => credential()).toThrow();
  });

  it('accepts a --label equal to the pinned one — the refusal is about the difference', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(
      ['--url', PINNED, '--label', 'example-prod', '--no-sync-history'],
      pinnedDeps(io),
    );
    expect(exits).toEqual([]);
    expect(io.output()).toContain('Attached to');
    expect(credential()).toMatchObject({ endpoint: PINNED });
  });

  it('lets a detach through as a no-op where the overlay holds the machine standalone', () => {
    // The detach refusal exists for a detach the next read would UNDO. A
    // machine pinned standalone reads as not attached — even with a deployment
    // named beside the mode — so there is nothing to undo, and the command says
    // so instead of refusing.
    const standalone: ManagedSettings = {
      specVersion: 1,
      organization: 'Example Org',
      values: { runMode: 'standalone', controlPlane: { endpoint: PINNED, label: 'example-prod' } },
      lockedFields: [],
    };
    const off = scriptedPrompter({ interactive: true });
    runDetach([], { ...deps(off), managedSettings: standalone });
    expect(exits).toEqual([]);
    expect(off.output()).toContain('This machine was not attached; nothing to do.');
  });

  it('an unmanaged machine may still re-attach to a different deployment', async () => {
    // The positive control: the pre-flight reads the overlay, not the user's
    // own descriptor, so moving between deployments stays the user's to do.
    await runAttach(
      ['--url', ENDPOINT, '--no-sync-history'],
      deps(scriptedPrompter({ interactive: true, answers: [KEY] })),
    );
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', OTHER, '--no-sync-history'], deps(io));
    expect(exits).toEqual([]);
    expect(io.output()).toContain('Attached to');
    expect(readWorkspaceSettings(base).controlPlane?.endpoint).toBe(OTHER);
    expect(credential()).toMatchObject({ endpoint: OTHER });
  });
});

describe('status', () => {
  it('reports standalone on a machine that has never attached', async () => {
    const io = scriptedPrompter({ interactive: true });
    await runStatus([], deps(io));
    expect(io.output()).toContain('not attached');
  });

  it('answers "whether policy is current", which the command summary promises', async () => {
    // The policy line is a second renderer because reading the cached bundle is
    // async while the connection block is sync and total. Without it the
    // command advertises an answer it never prints.
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT, '--no-sync-history'], deps(io));

    const out = scriptedPrompter({ interactive: true });
    await runStatus([], deps(out));
    expect(out.output()).toContain('policy');
    expect(out.output()).toContain('none cached');
  });

  it('reports the host version and the protections it is too old for', async () => {
    // The POSITIVE half of the pair below, and the one that guards the FEATURE.
    // The empty-cache case proves the guard is present; it passes identically
    // when the whole block is deleted, so on its own it cannot tell "guarded"
    // from "gone". This one seeds the cache a hook would have written and
    // asserts the block actually renders.
    mkdirSync(dataDirOf(base), { recursive: true });
    writeFileSync(
      join(dataDirOf(base), 'host-version.json'),
      JSON.stringify({ version: '2.0.0', observedAt: Date.now() }),
      'utf8',
    );

    const io = scriptedPrompter({ interactive: true });
    await runStatus([], deps(io));
    expect(io.output()).toContain('2.0.0');
    expect(io.output()).toContain('model-switch protection');
  });

  it('ends without a trailing blank line when there is no host reading yet', async () => {
    // `hostCompatibilityLines` returns [] on a machine no Claude Code hook has
    // ever written a version for — a CLI-only install, a Codex-only install, or
    // any Claude Code install before its first completed turn. Joining [] gives
    // '', so an unguarded template emits a bare newline on all three.
    //
    // Asserted on the BYTES rather than with `not.toContain`: a blank line is
    // the absence of content, so there is no substring to look for, and every
    // other assertion in this block stays green while it is there.
    const io = scriptedPrompter({ interactive: true });
    await runStatus([], deps(io));
    const out = io.output();
    expect(out.endsWith('\n')).toBe(true);
    expect(out.endsWith('\n\n')).toBe(false);
  });

  it('says nothing about policy on a machine with no attachment', async () => {
    // A standalone machine has no policy to be current, so the line would be
    // answering a question nobody asked.
    const io = scriptedPrompter({ interactive: true });
    await runStatus([], deps(io));
    expect(io.output()).not.toContain('policy');
  });

  it('names the deployment once attached, and never the key', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT, '--no-sync-history'], deps(io));

    const out = scriptedPrompter({ interactive: true });
    await runStatus([], deps(out));
    expect(out.output()).toContain(ENDPOINT);
    expectNoEchoOf(out.output(), KEY);
  });
});

/**
 * The second grant this command can take: permission to send the activity this
 * machine recorded BEFORE it attached. Separate from the attachment itself,
 * because attaching says where new activity goes and says nothing about what is
 * already on disk.
 */
describe('existing-history consent', () => {
  const consentOf = () => readWorkspaceSettings(base).historySyncConsent;

  // The question is only asked when there IS something to ask about, so a case
  // about the prompt has to give the machine a history to offer.
  const seedHistory = (): void => {
    const db = openLocalDatabase(dataDirOf(base));
    try {
      db.auditEvents.ensureSessionRoot('s-1', '2026-08-01T00:00:00.000Z');
    } finally {
      db.close();
    }
  };

  // A pre-attach CAPTURE — a prompt, unlike seedHistory's structural session.
  // Nothing marks this owed on its own: it is exactly the row a live forward
  // never touches, because it was recorded before the machine ever attached.
  const seedCapture = (): void => {
    const db = openLocalDatabase(dataDirOf(base));
    try {
      db.auditEvents.ensureSessionRoot('s-1', '2026-08-01T00:00:00.000Z');
      db.auditEvents.insertAuditEvent({
        id: 's-1-prompt',
        eventType: 'prompt',
        rootSessionId: 's-1',
        parentId: 's-1',
        startedAt: '2026-08-01T00:01:00.000Z',
        content: 'the text of a pre-attach prompt',
      });
    } finally {
      db.close();
    }
  };

  // v3: granting existing-history consent backfills the CAPTURE half too, not
  // only the structural drain's own backlog boundary. Before this, a capture
  // recorded while detached was structurally unreachable to any drain forever
  // — see markCaptureBacklogOwed.
  it('backfills a pre-existing capture as owed when the user grants consent', async () => {
    seedCapture();
    const io = scriptedPrompter({ interactive: true, answers: [KEY, 'y'] });
    await runAttach(['--url', ENDPOINT], deps(io));
    expect(consentOf()).toMatchObject({ endpoint: ENDPOINT });

    const db = openLocalDatabase(dataDirOf(base));
    try {
      expect(db.historySync.pendingCaptureRows(10, Date.now() + 1).map((r) => r.id)).toEqual([
        's-1-prompt',
      ]);
    } finally {
      db.close();
    }
  });

  // Declining must never mark anything owed — the backfill is downstream of a
  // real yes, not of the question having been asked.
  it('does not backfill a pre-existing capture when the user declines', async () => {
    seedCapture();
    const io = scriptedPrompter({ interactive: true, answers: [KEY, 'n'] });
    await runAttach(['--url', ENDPOINT], deps(io));
    expect(consentOf()).toBeUndefined();

    const db = openLocalDatabase(dataDirOf(base));
    try {
      expect(db.historySync.pendingCaptureRows(10, Date.now() + 1)).toEqual([]);
    } finally {
      db.close();
    }
  });

  // A machine that has never opened a store has recorded nothing. Asking there
  // offers to send a history that does not exist — and a yes records a grant
  // covering nothing.
  // v2 CHANGED THIS. Under v1 the grant's only subject was the pre-attach
  // backlog, so a machine with nothing recorded was asked nothing. v2 gave it a
  // second subject that exists on any machine — whether a capture the live path
  // FAILS to deliver is kept and retried or dropped — and a fresh machine is the
  // common case for a first attach. Skipping the question there would leave it
  // permanently ungranted and silently drop that traffic.
  it('still asks on a machine with no store, but offers no history numbers', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY, 'n'] });
    await runAttach(['--url', ENDPOINT], deps(io));
    expect(exits).toEqual([]);
    expect(consentOf()).toBeUndefined();
    const shown = io.output();
    // Asked about the half that has a subject...
    expect(shown).toContain('Saying no does not stop live sending');
    // ...and not about a backlog it does not have.
    expect(shown).not.toContain('What that history sends:');
    expect(shown).not.toContain('days of activity already recorded');
  });

  it('records the grant on a fresh machine when the user says yes', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY, 'y'] });
    await runAttach(['--url', ENDPOINT], deps(io));
    expect(consentOf()).toMatchObject({ endpoint: ENDPOINT });
  });

  it('records no grant when the flag declines, and asks nothing', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT, '--no-sync-history'], deps(io));
    expect(exits).toEqual([]);
    expect(consentOf()).toBeUndefined();
  });

  it('records a grant when the flag consents, and asks nothing', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT, '--sync-history'], deps(io));
    expect(exits).toEqual([]);
    expect(consentOf()).toMatchObject({
      endpoint: ENDPOINT,
      payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
    });
    expect(isHistorySyncConsentValid(consentOf(), ENDPOINT)).toBe(true);
  });

  // Contradictory flags are a refusal, not a silent precedence rule: which one
  // wins is exactly what the person typing them cannot know.
  it('refuses both flags together and changes nothing', () => {
    const parsed = parseAttachArgs(['--url', ENDPOINT, '--sync-history', '--no-sync-history']);
    expect(parsed).toEqual({
      error: '--sync-history and --no-sync-history are mutually exclusive',
    });
  });

  it('refuses them in the other order too', () => {
    const parsed = parseAttachArgs(['--url', ENDPOINT, '--no-sync-history', '--sync-history']);
    expect(parsed).toHaveProperty('error');
  });

  it('grants on an explicit yes', async () => {
    seedHistory();
    const io = scriptedPrompter({ interactive: true, answers: [KEY, 'Y'] });
    await runAttach(['--url', ENDPOINT], deps(io));
    expect(consentOf()).toMatchObject({ endpoint: ENDPOINT });
  });

  it('declines on no', async () => {
    seedHistory();
    const io = scriptedPrompter({ interactive: true, answers: [KEY, 'n'] });
    await runAttach(['--url', ENDPOINT], deps(io));
    expect(consentOf()).toBeUndefined();
  });

  // The default is decline: sending cannot be undone, so a bare Enter must not
  // be the answer that sends.
  it('declines on an empty answer', async () => {
    seedHistory();
    const io = scriptedPrompter({ interactive: true, answers: [KEY, ''] });
    await runAttach(['--url', ENDPOINT], deps(io));
    expect(consentOf()).toBeUndefined();
  });

  // The assertions are on the SUBSTANCE, not on headings. This prompt is the
  // only place many users will ever read what the grant covers, and the payload
  // it describes widened at v2 to include captured text — so the test pins the
  // three things that make the answer informed: what always goes, the fact that
  // an undelivered capture carries its TEXT, and what declining actually costs.
  // A heading match would have stayed green through exactly that widening.
  it('says what it is asking about before it asks', async () => {
    seedHistory();
    const io = scriptedPrompter({ interactive: true, answers: [KEY, 'n'] });
    await runAttach(['--url', ENDPOINT], deps(io));
    const shown = io.output();
    expect(shown).toContain('What that history sends:');
    // The v2 widening, stated where the user is deciding.
    expect(shown).toContain('INCLUDES ITS TEXT');
    // The masking is conditional, and the prompt has to say so: a span is
    // masked only where the policy assigned its detection is redact or block,
    // and every detection ships on monitor. A bare match on `masked` passed
    // just as well over the earlier copy, which promised a guarantee this
    // traffic does not carry — so pin the condition and the default too.
    expect(shown).toContain('only where that policy');
    expect(shown).toContain('is redact or block');
    expect(shown).toContain('every detection ships on monitor');
    expect(shown).not.toContain('Every secret AKA');
    // Declining must not read as "this turns off sending" — it does not.
    expect(shown).toContain('Saying no does not stop live sending');
    expect(shown).toContain('cannot be');
    expectNoEchoOf(shown, KEY);
  });

  // An unattended enrolment has no one to ask, so it attaches and declines —
  // rather than refusing to attach, or granting on the user's behalf.
  it('attaches without asking or granting when there is no terminal', async () => {
    seedHistory();
    const io = scriptedPrompter({ interactive: false, stdin: `${KEY}\n` });
    await runAttach(['--url', ENDPOINT, '--key-stdin'], deps(io));
    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).runMode).toBe('attached');
    expect(consentOf()).toBeUndefined();
    expect(io.errors()).toContain('no terminal to prompt on');
  });

  // Re-attaching to the SAME deployment is the ordinary path — it is how a key
  // is rotated — and a decline there must be RECORDED, not merged away. Omitting
  // the key instead of spelling the revocation preserves whatever grant is
  // already on file, so the user's explicit no would be discarded.
  it('clears an existing grant when the user declines on a re-attach', async () => {
    await runAttach(
      ['--url', ENDPOINT, '--sync-history'],
      deps(scriptedPrompter({ interactive: true, answers: [KEY] })),
    );
    expect(consentOf()).toBeDefined();

    seedHistory();
    await runAttach(
      ['--url', ENDPOINT],
      deps(scriptedPrompter({ interactive: true, answers: [KEY, 'n'] })),
    );
    expect(consentOf()).toBeUndefined();
  });

  it('clears an existing grant when the decline comes from a flag', async () => {
    await runAttach(
      ['--url', ENDPOINT, '--sync-history'],
      deps(scriptedPrompter({ interactive: true, answers: [KEY] })),
    );
    await runAttach(
      ['--url', ENDPOINT, '--no-sync-history'],
      deps(scriptedPrompter({ interactive: true, answers: [KEY] })),
    );
    expect(consentOf()).toBeUndefined();
  });

  // Detach hands the attached period to the live path and releases the drain's
  // boundary. Without it, a re-attach to the same deployment leaves the detached
  // window delivered by neither path — the fingerprint is unchanged, so the
  // boundary is never re-frozen.
  it('releases the history boundary on detach so a re-attach can set a new one', async () => {
    await runAttach(
      ['--url', ENDPOINT, '--sync-history'],
      deps(scriptedPrompter({ interactive: true, answers: [KEY] })),
    );
    const db = openLocalDatabase(dataDirOf(base));
    try {
      db.historySync.rearmFor('some-fingerprint', Date.parse('2026-08-01T00:00:00.000Z'));
      expect(db.historySync.deployment().backlogBefore).toBeDefined();
    } finally {
      db.close();
    }

    runDetach([], deps(scriptedPrompter({ interactive: true })));

    const after = openLocalDatabase(dataDirOf(base));
    try {
      expect(after.historySync.deployment().backlogBefore).toBeUndefined();
    } finally {
      after.close();
    }
  });

  // A grant names the deployment it was given for, so detaching from that
  // deployment must take the grant with it rather than leave it to apply to
  // whatever this machine attaches to next.
  it('is cleared by detach', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT, '--sync-history'], deps(io));
    expect(consentOf()).toBeDefined();

    runDetach([], deps(scriptedPrompter({ interactive: true })));
    expect(consentOf()).toBeUndefined();
  });
});

// Forwarding follows from the attachment, not from the history answer, so the
// sentences describing it belong to every attach that finishes — including the
// flag and no-terminal paths that never ask the question — and to none that
// does not.
describe('what a finished attach says it forwards', () => {
  const FORWARDING = [
    'Activity from here on is sent to that deployment automatically.',
    'So is the Data Shares register a scan records — destinations and call sites, never source text.',
  ];
  const occurrences = (text: string, needle: string): number => text.split(needle).length - 1;

  it.each(['--sync-history', '--no-sync-history'])(
    'says each once on an attach driven by %s, which asks nothing',
    async (flag) => {
      const io = scriptedPrompter({ interactive: true, answers: [KEY] });
      await runAttach(['--url', ENDPOINT, flag], deps(io));
      expect(exits).toEqual([]);
      expect(readWorkspaceSettings(base).runMode).toBe('attached');
      // The question was skipped, so nothing it prints can be what satisfied
      // the counts below.
      expect(io.output()).not.toContain('Saying no does not stop live sending');
      for (const sentence of FORWARDING) expect(occurrences(io.output(), sentence)).toBe(1);
    },
  );

  it('says each once on an attach with no terminal to ask on', async () => {
    const io = scriptedPrompter({ interactive: false, stdin: `${KEY}\n` });
    await runAttach(['--url', ENDPOINT, '--key-stdin'], deps(io));
    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).runMode).toBe('attached');
    // The skip is what this case is about, so pin that it happened.
    expect(io.errors()).toContain('no terminal to prompt on');
    for (const sentence of FORWARDING) expect(occurrences(io.output(), sentence)).toBe(1);
  });

  it('says each once on the interactive path, which also asks the question', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY, 'n'] });
    await runAttach(['--url', ENDPOINT], deps(io));
    expect(exits).toEqual([]);
    // The question really was shown, so a copy of either sentence left inside
    // it would be counted here.
    expect(io.output()).toContain('Saying no does not stop live sending');
    for (const sentence of FORWARDING) expect(occurrences(io.output(), sentence)).toBe(1);
  });

  it('says neither when the attach fails to save after the question was asked', async () => {
    // A directory where settings.json belongs makes the settings write fail,
    // which happens after the question — the path where a sentence printed by
    // the question would claim forwarding that never starts.
    mkdirSync(join(settingsDirOf(base), 'settings.json', 'occupied'), { recursive: true });
    const io = scriptedPrompter({ interactive: true, answers: [KEY, 'n'] });
    await runAttach(['--url', ENDPOINT], deps(io));
    expect(exits).toEqual([1]);
    expect(io.errors()).toContain('could not save the attachment');
    expect(io.output()).toContain('Saying no does not stop live sending');
    for (const sentence of FORWARDING) expect(io.output()).not.toContain(sentence);
  });
});
