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

const deps = (io: ReturnType<typeof scriptedPrompter>) => ({
  base,
  prompter: io,
  verify,
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
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT, '--home', base, '--no-sync-history'], {
      prompter: io,
      verify,
      exit: () => undefined,
    });
    expect(readWorkspaceSettings(base).runMode).toBe('attached');

    const out = scriptedPrompter({ interactive: true });
    await runStatus(['--home', base], { prompter: out, exit: () => undefined });
    expect(out.output()).toContain(ENDPOINT);

    const off = scriptedPrompter({ interactive: true });
    runDetach(['--home', base], { prompter: off, exit: () => undefined });
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

  // A machine that has never opened a store has recorded nothing. Asking there
  // offers to send a history that does not exist — and a yes records a grant
  // covering nothing.
  it('does not ask on a machine with no store at all', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT], deps(io));
    expect(exits).toEqual([]);
    expect(consentOf()).toBeUndefined();
    expect(io.output()).not.toContain('What that sends:');
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

  it('says what it is asking about before it asks', async () => {
    seedHistory();
    const io = scriptedPrompter({ interactive: true, answers: [KEY, 'n'] });
    await runAttach(['--url', ENDPOINT], deps(io));
    const shown = io.output();
    expect(shown).toContain('What that sends:');
    expect(shown).toContain('What it does not:');
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
