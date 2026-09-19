/**
 * Drives ALL FOUR real built Copilot hooks against hostile stdin.
 *
 * THIS PACKAGE IS THE ONLY ONE WHOSE TWO HALVES ASSERT OPPOSITE BYTES, because
 * one of its events has a different failure convention from the rest:
 *
 *  - `preToolUse` must print exactly one `{"permissionDecision":"allow"}` on
 *    every fault. Copilot CLI reads a hook that crashes or exits non-zero as a
 *    DENY, and its reading of exit-0-with-empty-stdout has never been observed
 *    (`test/fixtures/cli/README.md`, "Not measured"). Printing is correct under
 *    both readings, so the absence of a payload here is a regression that could
 *    wedge every tool call the user makes.
 *  - Every other hook must print NOTHING. Both hosts read silence on those
 *    events as "no opinion", and a payload they do not understand is at best
 *    ignored.
 *
 * So `''` is a PASS on three hooks and a FAILURE on the fourth, and the two
 * must never be checked by the same assertion.
 *
 * THE FAULT ROWS ALONE ARE NOT ENOUGH, and the reason is the same one the
 * Claude Code sibling records: an absence assertion over a hook that stopped
 * emitting entirely is satisfied for free. The enforcement block at the bottom
 * is the positive control — it drives a real finding through `preToolUse` at
 * block, redact-in-place, degraded-redact, warn and monitor, and asserts the
 * shape each cell owes. Keep both halves.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { withTempHome } from '../helpers/run-hook.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/e2e -> plugins/copilot
const PLUGIN_ROOT = join(HERE, '..', '..');
const script = (name: string): string => join(PLUGIN_ROOT, 'scripts', `${name}.js`);

/** What the CLI's "carry on unchanged" is spelled as on `preToolUse`. */
const CLI_ALLOW = { permissionDecision: 'allow' };

/**
 * Every built hook, with its argv and the bytes a faulting run owes the host.
 *
 * `prints: false` means the empty string, and it is asserted as an exact
 * equality rather than as "no decision key" — a hook that started printing an
 * unrecognised object would otherwise pass.
 */
const HOOKS = [
  { name: 'pre-tool-use', event: 'preToolUse', argv: [] as string[], prints: true },
  {
    name: 'session-start',
    event: 'sessionStart',
    argv: [join(PLUGIN_ROOT, 'plugin.json')],
    prints: false,
  },
  { name: 'user-prompt-submit', event: 'userPromptSubmitted', argv: [] as string[], prints: false },
  { name: 'post-tool-use', event: 'postToolUse', argv: [] as string[], prints: false },
] as const;

/**
 * Hostile stdin, one entry per way a payload can arrive broken.
 *
 * `oversized` exercises the READ direction — a payload far past the pipe buffer
 * the hook must consume without stalling or truncating its own answer. It is
 * deliberately NOT a test of the write-direction flush hazard: what a hook
 * emits here is at most thirty bytes, so no amount of oversized stdin can push
 * its stdout past the buffer. That property belongs to `emit` and is driven
 * directly in `test/hooks/fail-open-wrapper.test.ts`.
 */
const FAULTS: { label: string; input: string | Buffer }[] = [
  { label: 'empty stdin', input: '' },
  { label: 'malformed JSON', input: '{not json at all' },
  { label: 'truncated JSON', input: '{"toolName":"bash","toolArgs":{"command":"ec' },
  { label: 'a JSON scalar rather than an object', input: '"just-a-string"' },
  { label: 'JSON null', input: 'null' },
  { label: 'binary', input: Buffer.from([0x00, 0xff, 0xfe, 0x01, 0x02, 0x7f, 0x00]) },
  {
    label: 'oversized payload past the pipe buffer',
    input: JSON.stringify({
      sessionId: 'oversized-session',
      cwd: '/tmp',
      toolName: 'bash',
      toolArgs: { command: `echo ${'A'.repeat(1024 * 1024)}` },
    }),
  },
];

interface HookRun {
  stdout: string;
  stderr: string;
  status: number;
}

// spawnSync rather than execFileSync: execFileSync returns stdout ALONE and
// lets the child's stderr through to the parent, so a hook that exits 0 while
// writing a warning reads as having written nothing. stdout is the decision
// channel and must stay exactly one JSON object (or empty), so a once-per-
// session notice has nowhere else to go — leaving stderr uncaptured would make
// it unassertable.
function runHook(
  hookName: string,
  argv: readonly string[],
  home: string,
  input: string | Buffer,
): HookRun {
  const result = spawnSync(process.execPath, [script(hookName), ...argv], {
    env: { HOME: home, USERPROFILE: home },
    input,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  const { error, status, stdout, stderr } = result as unknown as {
    error?: Error;
    status: number | null;
    stdout: string | null;
    stderr: string | null;
  };
  if (error && stdout === null && stderr === null) {
    return { stdout: '', stderr: error.message, status: 1 };
  }
  return { stdout: stdout ?? '', stderr: stderr ?? '', status: status ?? 1 };
}

/**
 * Exactly one JSON object on stdout, and exit 0.
 *
 * `JSON.parse` over the WHOLE stdout is what forbids a SECOND object: two
 * concatenated objects do not parse, so a hook that wrote twice is read by the
 * host exactly as one that wrote nothing — a deny, on the event where that
 * matters.
 */
function soleObject(run: HookRun): unknown {
  expect(run.status).toBe(0);
  expect(run.stdout).not.toBe('');
  return JSON.parse(run.stdout) as unknown;
}

/**
 * Nothing at all on stdout, and exit 0.
 *
 * NOT `expect(stdout).not.toContain(…)`: every such check passes on `''`, which
 * is precisely the value under test here, so the assertion has to be an exact
 * equality or it says nothing.
 */
function silent(run: HookRun): void {
  expect(run.status).toBe(0);
  expect(run.stdout).toBe('');
}

function expectFailOpen(hook: (typeof HOOKS)[number], run: HookRun): void {
  if (hook.prints) expect(soleObject(run)).toEqual(CLI_ALLOW);
  else silent(run);
}

/**
 * The weaker assertion the two NON-stdin faults need, and why it is weaker on
 * purpose.
 *
 * A broken or relocated store is a condition AKA is designed to speak about:
 * the once-per-session store-unavailable notice, and the first-run nudge, are
 * both deliberate `systemMessage` writes on a hook whose ordinary answer is
 * silence. Demanding `''` there would forbid a feature rather than catch a
 * regression.
 *
 * What must still hold is the thing that actually matters on these events: the
 * hook may say something, but it may not DECIDE. So this allows silence or one
 * JSON object carrying `systemMessage` alone, and refuses any decision key of
 * either dialect — including a `permissionDecision` that a copy-paste from the
 * `preToolUse` path would introduce.
 */
function expectNoVerdict(run: HookRun): void {
  expect(run.status).toBe(0);
  if (run.stdout === '') return;
  const payload = JSON.parse(run.stdout) as Record<string, unknown>;
  expect(Object.keys(payload)).toEqual(['systemMessage']);
}

function expectFailOpenOrNote(hook: (typeof HOOKS)[number], run: HookRun): void {
  if (hook.prints) {
    // The verdict is non-negotiable on this event; the note may ride with it.
    const payload = soleObject(run) as Record<string, unknown>;
    expect(payload.permissionDecision).toBe('allow');
    expect(
      Object.keys(payload).every((key) => key === 'permissionDecision' || key === 'systemMessage'),
    ).toBe(true);
    return;
  }
  expectNoVerdict(run);
}

describe.each(HOOKS)(
  '$name built hook — fails open on every fault',
  (hook) => {
    it.each(FAULTS)(`exits 0 on $label`, (fault) => {
      // Each case gets its own throwaway home so a store one hook creates
      // cannot change how the next one behaves.
      const run = withTempHome(
        (home) => runHook(hook.name, [hook.event, ...hook.argv], home, fault.input),
        `aka-copilot-failopen-${hook.name}-`,
      );
      expectFailOpen(hook, run);
    });

    it('fails open over a store that cannot be opened', () => {
      // The fault that is not about stdin: the hook's own dependency is broken.
      // Not the "SQLite format 3\0" header, so the first PRAGMA fails
      // SQLITE_NOTADB.
      const run = withTempHome((home) => {
        const dataDir = join(home, '.aka', 'data');
        mkdirSync(dataDir, { recursive: true });
        writeFileSync(
          join(dataDir, 'aka.db'),
          'AKA corrupt-store fixture — not a database\n'.repeat(64),
        );
        return runHook(
          hook.name,
          [hook.event, ...hook.argv],
          home,
          JSON.stringify({
            sessionId: 'corrupt-session',
            cwd: '/tmp',
            prompt: 'hello',
            toolName: 'bash',
            toolArgs: { command: 'echo hello', description: 'say hello' },
            toolResult: { resultType: 'success', textResultForLlm: 'hello' },
          }),
        );
      }, `aka-copilot-failopen-${hook.name}-corrupt-`);
      expectFailOpenOrNote(hook, run);
    });

    /**
     * A hostile home is the fault class the corrupt-store case cannot reach:
     * the store opens PERFECTLY, so nothing is degraded — the corpus simply
     * lands somewhere the user did not choose. The decision channel must be
     * untouched by saying so, which is why the notice goes to stderr.
     */
    it('still fails open on a symlinked home, and says the store moved', (ctx) => {
      if (process.platform === 'win32') {
        ctx.skip('unprivileged symlink creation is not available on Windows');
        return;
      }
      let victim = '';
      const run = withTempHome((home) => {
        // Inside `home` so withTempHome's teardown removes it, and RESOLVED
        // because the reporter realpaths what it names.
        const target = join(home, 'victim');
        mkdirSync(target, { recursive: true });
        chmodSync(target, 0o755);
        symlinkSync(target, join(home, '.aka'));
        victim = realpathSync(target);
        return runHook(
          hook.name,
          [hook.event, ...hook.argv],
          home,
          JSON.stringify({
            sessionId: 'symlinked-session',
            cwd: '/tmp',
            prompt: 'hello',
            toolName: 'bash',
            toolArgs: { command: 'echo hello', description: 'say hello' },
            toolResult: { resultType: 'success', textResultForLlm: 'hello' },
          }),
        );
      }, `aka-copilot-failopen-${hook.name}-symlink-`);

      expectFailOpenOrNote(hook, run);
      expect(run.stderr).toContain('is a symlink');
      expect(run.stderr).toContain(victim);
      expect(run.stderr).toContain('NOT owner-only');
    });
  },
  60_000,
);

// ─── Enforcement, the positive control for every absence check above ─────────
//
// Without this block the three silent hooks' rows are satisfied by a build that
// emits nothing ever, and `preToolUse`'s rows are satisfied by one that allows
// everything. These drive a REAL finding from a shipped rule's own fixture
// through the built hook and assert the shape each policy owes.

const RULE_ID = 'secrets/twilio-key';
function secretFixture(): { namespace: string; packId: string; example: string } {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
  }
  return { namespace: pack.namespace, packId: pack.packId, example };
}
const FIXTURE = secretFixture();

function seedPolicy(home: string, policy: BuiltinPolicyId): void {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(FIXTURE.namespace, FIXTURE.packId, policy);
  } finally {
    db.close();
  }
}

/**
 * A `bash` call carrying the secret in the named field.
 *
 * WHICH FIELD IS THE WHOLE EXPERIMENT. `command` EXECUTES, so masking it would
 * change what runs and the runtime degrades a redact there into the configured
 * `redactFallback`. `description` is model-authored prose riding alongside, so
 * it can be masked in place and keeps true redaction. The recorded fixture
 * carries both, which is why the CLI field table has two rows.
 */
function runPreToolUse(home: string, field: 'command' | 'description') {
  const toolArgs =
    field === 'command'
      ? { command: `deploy ${FIXTURE.example}`, description: 'deploy the service' }
      : { command: 'deploy', description: `deploy with ${FIXTURE.example}` };
  return runHook(
    'pre-tool-use',
    ['preToolUse'],
    home,
    JSON.stringify({ sessionId: 'enforce-session', cwd: '/tmp', toolName: 'bash', toolArgs }),
  );
}

/**
 * The store-unavailable note is the one message `preToolUse` prints that is not
 * a verdict, and it must ride WITH the verdict rather than instead of it.
 *
 * `expectFailOpenOrNote` above cannot see this: it passes on a bare allow, so a
 * regression that dropped the note entirely would leave every fault row green
 * while the user's store silently stopped recording. And the opposite
 * regression — printing the note ALONE — is what this section's verdict
 * assertion exists to refuse, on an event where a payload the host has to
 * interpret is exactly the risk.
 */
describe('pre-tool-use over an unopenable store', () => {
  it('prints the allow AND the note, in one object', () => {
    const run = withTempHome((home) => {
      const dataDir = join(home, '.aka', 'data');
      mkdirSync(dataDir, { recursive: true });
      writeFileSync(join(dataDir, 'aka.db'), 'not a database\n'.repeat(64));
      return runHook(
        'pre-tool-use',
        ['preToolUse'],
        home,
        JSON.stringify({
          sessionId: 'store-note-session',
          cwd: '/tmp',
          toolName: 'bash',
          toolArgs: { command: 'echo hello', description: 'say hello' },
        }),
      );
    }, 'aka-copilot-store-note-');

    const payload = soleObject(run) as { permissionDecision?: string; systemMessage?: string };
    expect(payload.permissionDecision).toBe('allow');
    expect(payload.systemMessage ?? '').toContain('aka.db');
  });
});

describe('pre-tool-use enforcement — the four cells, against the built hook', () => {
  it('denies under a block policy', () => {
    const run = withTempHome((home) => {
      seedPolicy(home, 'block');
      return runPreToolUse(home, 'command');
    }, 'aka-copilot-enforce-block-');

    const decided = soleObject(run) as {
      permissionDecision?: string;
      permissionDecisionReason?: string;
    };
    expect(decided.permissionDecision).toBe('deny');
    expect(decided.permissionDecisionReason ?? '').toContain(RULE_ID);
    // The raw value must never ride back out in the reason.
    expect(run.stdout).not.toContain(FIXTURE.example);
  });

  it('rewrites in place under a redact policy, on a field that does not execute', () => {
    const run = withTempHome((home) => {
      seedPolicy(home, 'redact');
      return runPreToolUse(home, 'description');
    }, 'aka-copilot-enforce-redact-');

    const decided = soleObject(run) as { modifiedArgs?: Record<string, unknown> };
    expect(decided.modifiedArgs).toBeDefined();
    // The WHOLE argument object, not a diff: `modifiedArgs` replaces the call's
    // arguments, so an omitted key would drop it from the executed command.
    expect(decided.modifiedArgs?.command).toBe('deploy');
    expect(String(decided.modifiedArgs?.description)).not.toContain(FIXTURE.example);
    expect(run.stdout).not.toContain(FIXTURE.example);
  });

  /**
   * The same policy on the field that EXECUTES. Masking it would silently
   * change what runs, so the runtime degrades the redact into
   * `redactFallback` — which ships as `warn`, so the call goes through. This
   * is the cell most likely to be misread as a bug, and pinning it is what
   * stops someone "fixing" it into an unconditional deny.
   */
  it('lets the call through under the shipped warn fallback when the field executes', () => {
    const run = withTempHome((home) => {
      seedPolicy(home, 'redact');
      return runPreToolUse(home, 'command');
    }, 'aka-copilot-enforce-degraded-');

    const decided = soleObject(run) as { permissionDecision?: string; systemMessage?: string };
    expect(decided.permissionDecision).not.toBe('deny');
    expect(run.stdout).not.toContain(FIXTURE.example);
  });

  it('notes a warn policy without stopping the call', () => {
    const run = withTempHome((home) => {
      seedPolicy(home, 'warn');
      return runPreToolUse(home, 'command');
    }, 'aka-copilot-enforce-warn-');

    const decided = soleObject(run) as { systemMessage?: string };
    expect(decided.systemMessage ?? '').toContain(RULE_ID);
    expect(run.stdout).not.toContain(FIXTURE.example);
  });

  /**
   * Monitor is the shipped default and is the row that would make every other
   * one vacuous if the rule stopped matching: here the hook sees the finding,
   * records it, and still emits the plain allow.
   */
  it('emits the plain explicit allow under a monitor policy', () => {
    const run = withTempHome((home) => {
      seedPolicy(home, 'monitor');
      return runPreToolUse(home, 'command');
    }, 'aka-copilot-enforce-monitor-');

    expect(soleObject(run)).toEqual(CLI_ALLOW);
  });
});
