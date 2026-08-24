import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  controlPlaneCredentialPath,
  dataDir as dataDirOf,
  readWorkspaceSettings,
  settingsDir as settingsDirOf,
} from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

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
  rmSync(base, { recursive: true, force: true });
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
    await runAttach(['--url', ENDPOINT], deps(io));
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
    await runAttach(['--url', ENDPOINT, '--label', 'Example Org production'], deps(io));

    const credential: unknown = JSON.parse(
      readFileSync(controlPlaneCredentialPath(settingsDirOf(base)), 'utf8'),
    );
    expect(credential).toMatchObject({ endpoint: ENDPOINT, apiKey: KEY });

    const settings = readWorkspaceSettings(base);
    expect(settings.runMode).toBe('attached');
    expect(settings.controlPlane).toMatchObject({ endpoint: ENDPOINT, label: 'Example Org production' });
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

describe('detach', () => {
  it('clears both halves and everything derived from them', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT], deps(io));

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
  it('reports standalone on a machine that has never attached', () => {
    const io = scriptedPrompter({ interactive: true });
    runStatus([], deps(io));
    expect(io.output()).toContain('not attached');
  });

  it('names the deployment once attached, and never the key', async () => {
    const io = scriptedPrompter({ interactive: true, answers: [KEY] });
    await runAttach(['--url', ENDPOINT], deps(io));

    const out = scriptedPrompter({ interactive: true });
    runStatus([], deps(out));
    expect(out.output()).toContain(ENDPOINT);
    expectNoEchoOf(out.output(), KEY);
  });
});
