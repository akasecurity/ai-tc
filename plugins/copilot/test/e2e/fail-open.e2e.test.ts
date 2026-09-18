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
