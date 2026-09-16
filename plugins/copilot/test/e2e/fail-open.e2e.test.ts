// Drives the real BUILT pre-tool-use hook against hostile stdin, in both
// dialects, and then against a real finding at every enforcement level.
//
// The two halves are not optional alternatives. The **fault** rows prove the
// hook says something when it cannot decide: on the Copilot CLI a crashed or
// non-zero-exiting `preToolUse` hook is read as a DENY, and whether exit 0 with
// empty stdout allows or denies is unmeasured, so silence here is at best a
// coin-flip and at worst a blocked tool call. Every one of those rows is a
// PRESENCE check, which is the right shape on this event and the wrong one
// anywhere the absence of output means "no opinion".
//
// The **enforcement** rows are the positive control the fault rows cannot be
// without. `expect(stdout).not.toBe('')` says nothing about whether the hook
// can still decide anything, so a hook wired to print its allow and then return
// immediately would satisfy every fault row in this file. Only a row driving a
// real finding through a real policy can see that.
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
 * Assert the three things the host requires, in the order that makes a failure
 * readable: it exited 0, it said something, and what it said is exactly one
 * JSON object. `JSON.parse` over the WHOLE stdout is what forbids a second
 * object — two concatenated objects do not parse.
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

/** The two dialects, with the allow each host's schema accepts. */
const DIALECTS = [
  {
    event: 'preToolUse',
    allow: { permissionDecision: 'allow' },
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
    allow: { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } },
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
  'pre-tool-use built hook [$event] — fails open by PRINTING, on every fault',
  (d) => {
    it.each(FAULTS)('emits its explicit allow on $label', (fault) => {
      // Each case gets its own throwaway home so a store one run creates cannot
      // change how the next one behaves.
      const run = withTempHome(
        (home) => runHook(d.event, home, fault.input),
        `aka-copilot-failopen-${d.event}-`,
      );
      expect(soleObject(run)).toEqual(d.allow);
    });

    it('emits its explicit allow for a tool it has no field table for', () => {
      // The fast path, and under VS Code the COMMON one: matchers are parsed
      // and ignored there, so this hook is spawned for every tool call the
      // agent makes. It must still print.
      const payload = { ...d.call('ls'), toolName: 'read_file', tool_name: 'read_file' };
      const run = withTempHome(
        (home) => runHook(d.event, home, JSON.stringify(payload)),
        `aka-copilot-unknown-tool-${d.event}-`,
      );
      expect(soleObject(run)).toEqual(d.allow);
    });

    it('emits its explicit allow over a store that cannot be opened', () => {
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

      // The allow, and the degradation notice riding with it rather than
      // replacing it: a user whose store is gone is told detection is off, and
      // the call still goes through.
      const decided = soleObject(run) as Record<string, unknown>;
      expect(decided).toMatchObject(d.allow);
      expect(String(decided.systemMessage)).toContain('could not open its local store');
    });
  },
  60_000,
);

// ─── Enforcement, as the counterpart to the fault rows above ────────────────
//
// Every case above proves the hook says something when it CANNOT decide. These
// prove what it says when it can. Without them every `stdout !== ''` above is
// satisfied by a hook that prints its allow and returns.

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

  it('LETS THE COMMAND RUN under a redact policy on executable text, saying so', () => {
    // The shipped `redactFallback` is `warn`, and command text cannot be masked
    // in place — rewriting it would change what runs. So a redact policy here
    // resolves to a warn INSIDE the runtime, the call goes through, and the
    // only trace is a message. Pinned rather than left implicit, because it is
    // the surprising half of the fallback.
    const decided = soleObject(enforce('redact', COMMAND)) as Record<string, unknown>;
    expect(String(decided.systemMessage)).toContain('AKA flagged sensitive content');
    expect(JSON.stringify(decided)).not.toContain('modifiedArgs');
    expect(JSON.stringify(decided)).not.toContain('updatedInput');
  });

  it('WARNS under a warn policy', () => {
    const decided = soleObject(enforce('warn', COMMAND)) as Record<string, unknown>;
    expect(String(decided.systemMessage)).toContain(RULE_ID);
  });

  it('MONITORS silently — the allow, and nothing else', () => {
    // `monitor` records and says nothing, so what reaches stdout is the
    // wrapper's own explicit allow. On a host that may read silence as a deny,
    // "says nothing" still has to be a payload.
    expect(soleObject(enforce('monitor', COMMAND))).toEqual(d.allow);
  });

  it('allows a clean command under the block policy, so the block row is not vacuous', () => {
    // The control on the control. Without it, a hook that denied EVERYTHING
    // would satisfy the block case above.
    expect(soleObject(enforce('block', 'echo hello'))).toEqual(d.allow);
  });
});
