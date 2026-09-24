// Drives the real BUILT pre-tool-use hook against hostile stdin, in both
// dialects, and then against a real finding at every enforcement level.
//
// The two halves are not optional alternatives. The **fault** rows prove the
// hook reaches no verdict and says nothing while still exiting 0 — which is
// what fail-open means here. On the Copilot CLI `preToolUse` is the one
// fail-closed event, but the channel that fails closed is the EXIT CODE: the
// hooks reference denies on a non-zero exit other than 2 and on exit 2, and its
// `preToolUse` decision table reads "Empty output uses default behavior", so
// empty stdout hands the call to the host's own permission flow. Printing an
// allow there would instead PRE-APPROVE it.
//
// So every fault row is an ABSENCE check, and an absence check is worth nothing
// on its own: `expect(stdout).toBe('')` is satisfied by a hook that crashed
// before doing anything, by one built from an empty file, and by a broken
// harness that never spawned. The **enforcement** rows are what make them mean
// something — they drive a real finding through a real policy and show the same
// built script DOES write, so silence is a decision rather than a failure.
// Neither half survives without the other.
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { withTempHome } from '../helpers/run-hook.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/e2e -> plugins/copilot
const PLUGIN_ROOT = join(HERE, '..', '..');
const SCRIPT = join(PLUGIN_ROOT, 'scripts', 'pre-tool-use.js');
const MANIFEST = join(PLUGIN_ROOT, 'plugin.json');

interface HookRun {
  stdout: string;
  stderr: string;
  status: number;
}

// spawnSync rather than execFileSync: execFileSync returns stdout ALONE and
// lets the child's stderr through to the parent, so a hook that exits 0 while
// writing a warning reads as having written nothing. stdout here is the
// decision channel and must stay exactly one JSON object, so a once-per-session
// notice has nowhere else to go — leaving stderr uncaptured would make it
// unassertable.
function runHook(event: string, home: string, input: string | Buffer): HookRun {
  const result = spawnSync(process.execPath, [SCRIPT, event, MANIFEST], {
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
 * Assert the three things the host requires of a run that DECIDED, in the order
 * that makes a failure readable: it exited 0, it said something, and what it
 * said is exactly one JSON object. `JSON.parse` over the WHOLE stdout is what
 * forbids a second object — two concatenated objects do not parse.
 *
 * Exit 0 rather than "not 2": a non-zero exit is a deny on the CLI, and under
 * VS Code 2 specifically is the block channel, so either would be an
 * enforcement decision taken by a route this package never writes to.
 */
function soleObject(run: HookRun): unknown {
  expect(run.status, run.stderr).toBe(0);
  expect(run.stdout).not.toBe('');
  return JSON.parse(run.stdout) as unknown;
}

/**
 * Assert a run reached no verdict: exit 0, and NOTHING on stdout.
 *
 * Exit 0 is asserted first and carries `stderr` as its message, because that is
 * the half that would actually deny the tool call — a hook that crashed also
 * writes no stdout, and without this the two are indistinguishable.
 */
function noObject(run: HookRun): void {
  expect(run.status, run.stderr).toBe(0);
  expect(run.stdout).toBe('');
}

/**
 * The two payload dialects.
 *
 * Only `preToolUse` is registered in `hooks.json` — the CLI honours a PascalCase
 * key too and would spawn this script a second time per tool call — but the
 * PascalCase entry is still driven here, by argv, because the snake_case code
 * path is real and is what a VS Code delivery will use.
 */
const DIALECTS = [
  {
    event: 'preToolUse',
    call: (command: string) => ({
      sessionId: 'c1779e76-9889-419b-ab12-f7bb8a957e15',
      timestamp: 1788547866483,
      cwd: '/tmp',
      toolName: 'bash',
      toolArgs: { command, description: 'e2e', mode: 'sync', initial_wait: 30 },
    }),
  },
  {
    event: 'PreToolUse',
    call: (command: string) => ({
      hook_event_name: 'PreToolUse',
      session_id: 'c1779e76-9889-419b-ab12-f7bb8a957e15',
      timestamp: 1788547866483,
      cwd: '/tmp',
      tool_name: 'run_in_terminal',
      tool_input: { command, explanation: 'e2e', isBackground: false },
    }),
  },
] as const;

/**
 * Hostile stdin, one entry per way a payload can arrive broken.
 *
 * `oversized` exercises the READ direction — a payload far past the pipe buffer
 * that the hook must consume without stalling or truncating its own answer. It
 * is deliberately NOT a test of the write-direction flush hazard: what this
 * hook emits is around thirty bytes, so no amount of oversized stdin can push
 * its stdout past the buffer. That property belongs to `emit` and is driven
 * directly in `test/hooks/fail-open-wrapper.test.ts`.
 */
const FAULTS: { label: string; input: string | Buffer }[] = [
  { label: 'empty stdin', input: '' },
  { label: 'malformed JSON', input: '{not json at all' },
  { label: 'truncated JSON', input: '{"toolName":"bash","toolArgs":{"command":"ec' },
  { label: 'a JSON scalar rather than an object', input: '"just-a-string"' },
  { label: 'JSON null', input: 'null' },
  { label: 'a JSON array', input: '[{"toolName":"bash"}]' },
  { label: 'binary', input: Buffer.from([0x00, 0xff, 0xfe, 0x01, 0x02, 0x7f, 0x00]) },
  {
    label: 'an envelope matching neither dialect',
    input: JSON.stringify({ toolName: 'bash', toolArgs: { command: 'ls' } }),
  },
  {
    label: 'oversized payload past the pipe buffer',
    input: JSON.stringify({
      sessionId: 'oversized',
      cwd: '/tmp',
      toolName: 'bash',
      toolArgs: { command: `echo ${'A'.repeat(1024 * 1024)}` },
    }),
  },
];

describe.each(DIALECTS)(
  'pre-tool-use built hook [$event] — fails open by EXITING 0 and saying nothing',
  (d) => {
    it.each(FAULTS)('reaches no verdict and writes nothing on $label', (fault) => {
      // Each case gets its own throwaway home so a store one run creates cannot
      // change how the next one behaves.
      const run = withTempHome(
        (home) => runHook(d.event, home, fault.input),
        `aka-copilot-failopen-${d.event}-`,
      );
      noObject(run);
    });

    it('writes nothing for a tool it has no field table for', () => {
      // The fast path, and under VS Code the COMMON one: matchers are parsed
      // and ignored there, so this hook is spawned for every tool call the
      // agent makes — `read_file`, `fetch_webpage`, every `mcp_*`. An allow per
      // spawn would pre-approve the agent's entire tool stream.
      const payload = { ...d.call('ls'), toolName: 'read_file', tool_name: 'read_file' };
      const run = withTempHome(
        (home) => runHook(d.event, home, JSON.stringify(payload)),
        `aka-copilot-unknown-tool-${d.event}-`,
      );
      noObject(run);
    });

    it('warns without a verdict over a store that cannot be opened', () => {
      // The fault that is not about stdin: the hook's own dependency is broken.
      // Not the "SQLite format 3\0" header, so the first PRAGMA fails
      // SQLITE_NOTADB.
      //
      // Note what this does and does not reach. `openGatewayOrNull` catches the
      // open failure and returns null by design, so the body still returns a
      // normal answer — this proves the degraded path answers, NOT that the
      // wrapper's catch works. No fault available here makes a body throw after
      // the store opens, so the wrapper's throw branch is covered by
      // `test/hooks/fail-open-wrapper.test.ts` and by nothing at this tier.
      const run = withTempHome((home) => {
        const dataDir = join(home, '.aka', 'data');
        mkdirSync(dataDir, { recursive: true });
        writeFileSync(
          join(dataDir, 'aka.db'),
          'AKA corrupt-store fixture — not a database\n'.repeat(64),
        );
        return runHook(d.event, home, JSON.stringify(d.call('echo hello')));
      }, `aka-copilot-corrupt-${d.event}-`);

      // The user is told detection is off and the call still goes through — but
      // NOT by pre-approving it. This is the state in which AKA has scanned
      // nothing, so it is the last place an allow belongs.
      //
      // Which channel carries the notice is the dialect's, and the assertion
      // follows it rather than searching both: VS Code documents
      // `systemMessage` on stdout, the CLI documents no message field at all
      // and so gets stderr. Asserting the OTHER channel is empty in each case is
      // what stops the CLI drifting back to a payload the host discards.
      if (d.event === 'preToolUse') {
        noObject(run);
        expect(run.stderr).toContain('could not open its local store');
      } else {
        const decided = soleObject(run) as Record<string, unknown>;
        expect(String(decided.systemMessage)).toContain('could not open its local store');
        expect(JSON.stringify(decided)).not.toContain('permissionDecision');
      }
    });
  },
  60_000,
);

// ─── Enforcement, as the counterpart to the fault rows above ────────────────
//
// Every case above proves the hook stays silent when it CANNOT decide. These
// prove it still speaks when it can. Without them every `stdout === ''` above
// is satisfied by a hook that was never built, never spawned, or crashed on
// import — the exact failures an absence check cannot tell apart from success.

const RULE_ID = 'secrets/twilio-key';
function secretFixture(): { namespace: string; packId: string; example: string } {
  // Taken from the rule's own examples rather than written here: this
  // repository is public, and a credential-shaped literal does not belong in it.
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

describe.each(DIALECTS)('pre-tool-use enforcement [$event]', (d) => {
  function enforce(policy: BuiltinPolicyId, command: string): HookRun {
    return withTempHome((home) => {
      seedPolicy(home, policy);
      return runHook(d.event, home, JSON.stringify(d.call(command)));
    }, `aka-copilot-enforce-${policy}-${d.event}-`);
  }

  /**
   * The message this dialect's user actually sees, read from the channel that
   * dialect has one on: stdout's `systemMessage` under VS Code, stderr on the
   * CLI, whose documented `preToolUse` output has no message field.
   *
   * Reading the dialect's own channel rather than concatenating both is the
   * point — a CLI build that went back to putting a `systemMessage` on stdout
   * would satisfy a both-channels search and fail here, which is the direction
   * that matters.
   */
  function notice(run: HookRun): string {
    if (d.event === 'preToolUse') return run.stderr;
    const decided = soleObject(run) as Record<string, unknown>;
    return String(decided.systemMessage);
  }

  const COMMAND = `deploy ${FIXTURE.example}`;

  it('BLOCKS under an explicit block policy, naming the rule', () => {
    const decided = soleObject(enforce('block', COMMAND)) as Record<string, unknown>;
    // Read through the dialect's own shape: a deny built in the other one would
    // be a valid JSON object the host does not understand, which is the failure
    // this whole package is arranged to prevent.
    const verdict =
      d.event === 'preToolUse'
        ? decided
        : (decided.hookSpecificOutput as Record<string, unknown> | undefined);
    expect(verdict?.permissionDecision).toBe('deny');
    expect(String(verdict?.permissionDecisionReason)).toContain(RULE_ID);
  });

  it('LETS THE COMMAND RUN under a redact policy on executable text, with NO verdict', () => {
    // The shipped `redactFallback` is `warn`, and command text cannot be masked
    // in place — rewriting it would change what runs. So a redact policy here
    // resolves to a warn INSIDE the runtime and the call goes through.
    //
    // Asserted as the VERDICT rather than as the message text, which is what
    // this row was missing: "the call goes through" on this host is the ABSENCE
    // of a decision. An `allow` emitted here would pre-approve a call AKA had
    // just flagged, suppressing the prompt the user's own Copilot settings
    // would have raised — strictly worse than not running at all.
    const run = enforce('redact', COMMAND);
    // Per dialect, because `not.toContain` against an empty string asserts
    // NOTHING — the vacuity CLAUDE.md §1 names. On the CLI the claim is that
    // stdout is exactly empty; only on VS Code, where a payload really is
    // written, does forbidding the three keys inside it mean anything.
    if (d.event === 'preToolUse') {
      noObject(run);
    } else {
      expect(run.status, run.stderr).toBe(0);
      expect(run.stdout).not.toBe('');
      expect(run.stdout).not.toContain('permissionDecision');
      expect(run.stdout).not.toContain('modifiedArgs');
      expect(run.stdout).not.toContain('updatedInput');
    }
    expect(notice(run)).toContain('AKA flagged sensitive content');
  });

  it('WARNS under a warn policy, naming the rule, and still with no verdict', () => {
    const run = enforce('warn', COMMAND);
    if (d.event === 'preToolUse') {
      noObject(run);
    } else {
      expect(run.status, run.stderr).toBe(0);
      expect(run.stdout).not.toBe('');
      expect(run.stdout).not.toContain('permissionDecision');
    }
    expect(notice(run)).toContain(RULE_ID);
  });

  it('MONITORS silently — nothing on either channel', () => {
    // `monitor` records and says nothing. Both channels are asserted: a notice
    // on stderr here would be a warning the operator never configured, and it
    // would be invisible to a stdout-only check.
    const run = enforce('monitor', COMMAND);
    noObject(run);
    expect(run.stderr).not.toContain('AKA flagged');
  });

  it('says nothing for a clean command under the block policy, so the block row is not vacuous', () => {
    // The control on the control. Without it, a hook that denied EVERYTHING
    // would satisfy the block case above.
    noObject(enforce('block', 'echo hello'));
  });
});

// ─── The three CAPTURE hooks ────────────────────────────────────────────────
//
// `sessionStart`, `userPromptSubmitted` and `postToolUse` enforce nothing —
// none of them can stop or rewrite anything on either host — so the exit code
// is the whole of what they owe the host, exactly as it is for `preToolUse`.
// Nothing above reaches them: each is its own built script, so a fault the
// pre-tool-use rows prove is handled says nothing about these three.
//
// The same two halves apply. The fault rows are absence checks and prove
// nothing alone; the control beside each one is what shows the script DOES the
// work it stayed silent about. For the two that can speak, the control reads
// their message. For `session-start.js`, which emits nothing on any path, the
// control is the SESSION ROW it leaves in the store — the only observable that
// separates "declined quietly" from "was never built".

const CAPTURE_HOOKS = [
  { script: 'session-start.js', cli: 'sessionStart', vscode: 'SessionStart' },
  { script: 'user-prompt-submit.js', cli: 'userPromptSubmitted', vscode: 'UserPromptSubmit' },
  { script: 'post-tool-use.js', cli: 'postToolUse', vscode: 'PostToolUse' },
] as const;

function runScript(script: string, event: string, home: string, input: string | Buffer): HookRun {
  const result = spawnSync(
    process.execPath,
    [join(PLUGIN_ROOT, 'scripts', script), event, MANIFEST],
    {
      env: { HOME: home, USERPROFILE: home },
      input,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
    },
  );
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

describe.each(CAPTURE_HOOKS)('$script — fails open by EXITING 0 and saying nothing', (hook) => {
  // Both event tokens, because each script handles both dialects and a fault
  // can be reached through either.
  const events = [hook.cli, hook.vscode];

  it.each(events.flatMap((event) => FAULTS.map((fault) => ({ event, ...fault }))))(
    'reaches no verdict and writes nothing on $label [$event]',
    (fault) => {
      const run = withTempHome(
        (home) => runScript(hook.script, fault.event, home, fault.input),
        `aka-copilot-failopen-${hook.script}-`,
      );
      noObject(run);
    },
  );

  it.each(events)('writes nothing over a store that cannot be opened [%s]', (event) => {
    // Not the "SQLite format 3\0" header, so the first PRAGMA fails
    // SQLITE_NOTADB. `openGatewayOrNull` catches it and the body returns a
    // normal answer, so this proves the degraded path answers — not that the
    // wrapper's catch works, which `test/hooks/fail-open-wrapper.test.ts` owns.
    const run = withTempHome((home) => {
      const dataDir = join(home, '.aka', 'data');
      mkdirSync(dataDir, { recursive: true });
      writeFileSync(
        join(dataDir, 'aka.db'),
        'AKA corrupt-store fixture — not a database\n'.repeat(64),
      );
      return runScript(
        hook.script,
        event,
        home,
        JSON.stringify(capturePayload(hook.script, event, 'echo hello')),
      );
    }, `aka-copilot-corrupt-${hook.script}-`);

    // The CLI has no message field on any of these three events, so its notice
    // is stderr and stdout stays exactly empty. On VS Code the two that can
    // speak carry it on stdout; `session-start.js` never emits on either host.
    if (event === hook.cli || hook.script === 'session-start.js') {
      noObject(run);
    } else {
      const decided = soleObject(run) as Record<string, unknown>;
      expect(String(decided.systemMessage)).toContain('could not open its local store');
    }
    // No verdict on ANY of these paths, on either dialect — these three hooks
    // have no enforcement channel at all, so a key from one is a defect
    // whichever channel it appeared on.
    expect(run.stdout).not.toContain('permissionDecision');
    expect(run.stdout).not.toContain('"decision"');
    expect(run.stdout).not.toContain('modifiedResult');
  });
});

/**
 * A well-formed payload for one of the three capture scripts, in the dialect
 * the event token selects.
 *
 * `text` is where the scannable content goes, which is a different field per
 * script — the prompt, the tool result, or nothing at all for a session start.
 * Built here rather than per case so the fault rows and the controls below
 * drive the same shapes.
 */
function capturePayload(script: string, event: string, text: string): Record<string, unknown> {
  // The CASING is what selects the dialect on this host — the CLI's own
  // reference says so — so it is what selects the envelope built here.
  const vscode = /^[A-Z]/u.test(event);
  const envelope = vscode
    ? { hook_event_name: event, session_id: SESSION_ID, cwd: '/tmp' }
    : { sessionId: SESSION_ID, timestamp: 1788547866483, cwd: '/tmp' };
  if (script === 'session-start.js') return { ...envelope, source: 'new' };
  if (script === 'user-prompt-submit.js') return { ...envelope, prompt: text };
  return vscode
    ? {
        ...envelope,
        tool_name: 'run_in_terminal',
        tool_input: { command: 'cat x' },
        tool_response: text,
      }
    : {
        ...envelope,
        toolName: 'bash',
        toolArgs: { command: 'cat x' },
        toolResult: { resultType: 'success', textResultForLlm: text },
      };
}

const SESSION_ID = 'c1779e76-9889-419b-ab12-f7bb8a957e15';

// `config.onboarded` is `settings.onboardedAt != null` — the single field that
// decides whether a clean prompt is silent or carries the calibration nudge.
function markOnboarded(home: string): void {
  const dir = join(home, '.aka', 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'settings.json'),
    JSON.stringify({ onboardedAt: '2026-01-01T00:00:00Z' }),
  );
}

// ─── The controls, without which every absence row above is vacuous ─────────

describe('session-start built hook — the control is the row it leaves, not a payload', () => {
  // This script emits NOTHING on any path on either host, so no stdout
  // assertion can separate "declined" from "was never built". The session root
  // it opens is the only observable that can, which is why the control for this
  // one script reads the store rather than the wire.
  it.each(['sessionStart', 'SessionStart'])(
    'opens a session root in a real store [%s]',
    (event) => {
      withTempHome((home) => {
        const run = runScript(
          'session-start.js',
          event,
          home,
          JSON.stringify(capturePayload('session-start.js', event, '')),
        );
        // Silent and clean — the property every other row here asserts.
        noObject(run);

        const db = new DatabaseSync(join(home, '.aka', 'data', 'aka.db'));
        try {
          const rows = db.prepare("SELECT id FROM audit_events WHERE event_type = 'session'").all();
          expect(rows).toEqual([{ id: SESSION_ID }]);
        } finally {
          db.close();
        }
      }, `aka-copilot-sessionstart-control-${event}-`);
    },
    60_000,
  );
});

describe.each(DIALECTS.map((d) => (d.event === 'preToolUse' ? 'cli' : 'vscode')))(
  'the two capture hooks that CAN speak do speak [%s]',
  (kind) => {
    const isCli = kind === 'cli';

    /** The channel this dialect actually has for a message on these events. */
    function notice(run: HookRun): string {
      if (isCli) {
        // The CLI documents no message field on either event, so stdout must be
        // exactly empty — asserted rather than ignored, because a build that
        // drifted back to a stdout `systemMessage` would still satisfy a search
        // across both channels.
        expect(run.stdout).toBe('');
        return run.stderr;
      }
      return String((soleObject(run) as Record<string, unknown>).systemMessage);
    }

    function speak(script: string, event: string): HookRun {
      return withTempHome((home) => {
        seedPolicy(home, 'warn');
        return runScript(
          script,
          event,
          home,
          JSON.stringify(capturePayload(script, event, `deploy ${FIXTURE.example}`)),
        );
      }, `aka-copilot-speak-${script}-${kind}-`);
    }

    it('user-prompt-submit names the rule and says the prompt went out unchanged', () => {
      const run = speak(
        'user-prompt-submit.js',
        isCli ? 'userPromptSubmitted' : 'UserPromptSubmit',
      );
      expect(run.status, run.stderr).toBe(0);
      const text = notice(run);
      expect(text).toContain(RULE_ID);
      expect(text).toContain('unchanged');
      // No verdict, ever: there is no prompt-stop channel on either host that
      // this repository has confirmed, and exit 2 is VS Code's block channel.
      expect(run.status).not.toBe(2);
      expect(run.stdout).not.toContain('permissionDecision');
      expect(run.stdout).not.toContain('"decision"');
    });

    it('post-tool-use names the rule and says the output reached the model', () => {
      const run = speak('post-tool-use.js', isCli ? 'postToolUse' : 'PostToolUse');
      expect(run.status, run.stderr).toBe(0);
      const text = notice(run);
      expect(text).toContain(RULE_ID);
      expect(text).toContain('reached the model');
      // The claim this path may never make — the tool has already run and the
      // result was not withheld.
      expect(text).not.toMatch(/never reached|withheld/iu);
      expect(run.stdout).not.toContain('modifiedResult');
      expect(run.stdout).not.toContain('"decision"');
    });

    it('says nothing at all for clean text, so the two rows above are not vacuous', () => {
      // The control on the controls: a hook that spoke on every capture would
      // satisfy both cases above.
      //
      // `markOnboarded` is load-bearing rather than tidying. On an unonboarded
      // home a clean SUBMITTED prompt carries the first-run calibration nudge,
      // which is correct behaviour and not a flag — so without it this case
      // would have to weaken to "said nothing about a finding", and a hook that
      // printed a flag message under another wording would slip through. With
      // it the claim stays exact: nothing at all.
      for (const [script, event] of [
        ['user-prompt-submit.js', isCli ? 'userPromptSubmitted' : 'UserPromptSubmit'],
        ['post-tool-use.js', isCli ? 'postToolUse' : 'PostToolUse'],
      ] as const) {
        const run = withTempHome((home) => {
          seedPolicy(home, 'warn');
          markOnboarded(home);
          return runScript(
            script,
            event,
            home,
            JSON.stringify(capturePayload(script, event, 'nothing to see here')),
          );
        }, `aka-copilot-clean-${script}-${kind}-`);
        noObject(run);
        // Not `toBe('')`: node prints its own `ExperimentalWarning` for
        // node:sqlite on this channel, which belongs to the runtime rather
        // than to the hook. Every message this package writes names itself, so
        // the absence of that name is the exact claim — and it holds whatever
        // wording a future notice takes, which `not.toContain('AKA flagged')`
        // would not.
        expect(run.stderr).not.toMatch(/\bAKA\b/u);
      }
    });

    it('carries the first-run nudge on a clean prompt when the home is NOT onboarded', () => {
      // Attributes the silence above to `onboardedAt` specifically. Without
      // this the case above passes just as well against a hook that lost the
      // nudge entirely, and the nudge is the only thing that tells a new user
      // AKA is running at all.
      const run = withTempHome((home) => {
        seedPolicy(home, 'warn');
        return runScript(
          'user-prompt-submit.js',
          isCli ? 'userPromptSubmitted' : 'UserPromptSubmit',
          home,
          JSON.stringify(
            capturePayload(
              'user-prompt-submit.js',
              isCli ? 'userPromptSubmitted' : 'UserPromptSubmit',
              'nothing to see here',
            ),
          ),
        );
      }, `aka-copilot-nudge-${kind}-`);
      expect(run.status, run.stderr).toBe(0);
      expect(notice(run)).toContain('AKA is active');
    });
  },
  120_000,
);
