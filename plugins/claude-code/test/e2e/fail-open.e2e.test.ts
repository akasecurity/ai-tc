/**
 * CLAUDE.md's first principle: the plugin must never break a user's Claude
 * session. Every one of the five hook entry points wraps main() in a
 * try/catch that falls back to writing nothing and exiting 0 — "allow" is
 * silence, not a JSON decision. This suite drives the REAL built scripts
 * (via runHook, from test/helpers/run-hook.ts) through the malformed-input
 * and unavailable-store matrix the fail-open contract exists for, plus a
 * regression pin on the wire protocol itself: no hook shape ever carries an
 * `action` key (that's an internal CaptureResult field, never serialized).
 */
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const SESSION_ID = 'fail-open-e2e-session';

function projectDir(home: string): string {
  const dir = join(home, 'project');
  mkdirSync(dir, { recursive: true });
  return dir;
}

interface HookCase {
  readonly name: string;
  // Builds a valid, store-touching payload for this hook under the given
  // temp home. Must actually reach the store-open code path (not just be
  // well-formed JSON) so the corrupt-store/read-only-home rows in Task 3/4
  // exercise something real.
  readonly validPayload: (home: string) => string;
}

const HOOKS: readonly HookCase[] = [
  {
    name: 'session-start',
    validPayload: (home) =>
      JSON.stringify({
        session_id: SESSION_ID,
        cwd: projectDir(home),
        hook_event_name: 'SessionStart',
        source: 'startup',
      }),
  },
  {
    name: 'user-prompt-submit',
    validPayload: (home) =>
      JSON.stringify({
        prompt: 'what does this function do?',
        session_id: SESSION_ID,
        cwd: projectDir(home),
        hook_event_name: 'UserPromptSubmit',
      }),
  },
  {
    // Bash's `command` field is in pre-tool-use-fields.ts's STATIC_FIELDS map,
    // so this reaches the store — unlike Read (used by the harness smoke
    // test), which has no field mapping and short-circuits before the store
    // ever opens.
    name: 'pre-tool-use',
    validPayload: (home) =>
      JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'echo hello' },
        session_id: SESSION_ID,
        cwd: projectDir(home),
        hook_event_name: 'PreToolUse',
      }),
  },
  {
    // Bash's stdout/stderr fields are in tool-response.ts's RESPONSE_TEXT_PATHS
    // map, so this reaches the store — unlike Read with a bare {content}
    // (used by the harness smoke test), which needs {file:{content}} and
    // short-circuits before the store ever opens.
    name: 'post-tool-use',
    validPayload: (home) =>
      JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'echo hello' },
        tool_response: { stdout: 'hello\n', stderr: '' },
        session_id: SESSION_ID,
        cwd: projectDir(home),
        hook_event_name: 'PostToolUse',
      }),
  },
  {
    // Unlike the other four hooks, stop.ts never opens the store in-process —
    // it only triggers a detached, unref'd reconcile.js worker. Its two
    // store-condition rows below still verify the PARENT process fails open
    // (which it does unconditionally), not that a corrupt/read-only store is
    // observed synchronously.
    name: 'stop',
    validPayload: (home) => {
      const cwd = projectDir(home);
      return JSON.stringify({
        session_id: SESSION_ID,
        transcript_path: join(cwd, 'transcript.jsonl'),
        cwd,
        hook_event_name: 'Stop',
        stop_hook_active: false,
      });
    },
  },
];

// CLAUDE.md §1: "no hook ever emits {action:'allow'}, and the internal fallback
// is {action:'log'}" — `action` is a CaptureResult field that never crosses the
// wire, and none of the shapes in the `HookOutput` union uses that key (which
// shapes those are is pinned by test/hook-output-shapes.test.ts). This guards
// against a refactor that starts serializing the internal decision object onto
// stdout.
//
// It is worth nothing on an EMPTY stdout, which every `expectFailsOpen` row
// below has already asserted — `''` matches no pattern, so the check there is a
// statement of intent rather than a test. What gives it teeth is the enforcement
// matrix at the bottom of this file: real findings, driven through the built
// hooks at every action level, each producing a payload this then reads.
function expectNoActionKey(stdout: string): void {
  expect(stdout).not.toMatch(/"action"\s*:/);
}

function expectFailsOpen(status: number, stdout: string): void {
  expect(status).toBe(0);
  expect(stdout).toBe('');
  expectNoActionKey(stdout);
}

describe('fail-open: malformed/hostile input never breaks a hook', () => {
  const MALFORMED_JSON = '{ this is not valid json #$%^&*';
  const TRUNCATED_JSON = '{"session_id": "fail-open-e2e-session", "cwd": "/tmp/unterminated';
  // Non-text control/high-byte content, repeated — never valid JSON, never
  // printable text. (execFileSync's `input` option is UTF-8 encoded from a JS
  // string, so this can't carry byte sequences with no valid Unicode
  // interpretation — but it still stresses readStdin()/JSON.parse with dense
  // control-character and NUL-byte content, which is the failure mode this
  // row exists to catch.)
  const BINARY_STDIN = Array.from({ length: 256 }, (_, i) => String.fromCharCode(i))
    .join('')
    .repeat(4);
  const HUGE_STDIN = 'x'.repeat(100 * 1024 * 1024); // 100 MB, not valid JSON

  for (const hook of HOOKS) {
    describe(hook.name, () => {
      it('malformed JSON → exit 0, empty stdout', () => {
        withTempHome((home) => {
          const result = runHook(hook.name, MALFORMED_JSON, { env: tempHomeEnv(home) });
          expectFailsOpen(result.status, result.stdout);
        });
      });

      it('empty stdin → exit 0, empty stdout', () => {
        withTempHome((home) => {
          const result = runHook(hook.name, '', { env: tempHomeEnv(home) });
          expectFailsOpen(result.status, result.stdout);
        });
      });

      it('truncated JSON → exit 0, empty stdout', () => {
        withTempHome((home) => {
          const result = runHook(hook.name, TRUNCATED_JSON, { env: tempHomeEnv(home) });
          expectFailsOpen(result.status, result.stdout);
        });
      });

      it('binary stdin → exit 0, empty stdout', () => {
        withTempHome((home) => {
          const result = runHook(hook.name, BINARY_STDIN, { env: tempHomeEnv(home) });
          expectFailsOpen(result.status, result.stdout);
        });
      });

      it('100 MB stdin → exit 0, empty stdout, no OOM', () => {
        withTempHome((home) => {
          const result = runHook(hook.name, HUGE_STDIN, {
            env: tempHomeEnv(home),
            timeoutMs: 30_000,
          });
          expectFailsOpen(result.status, result.stdout);
        });
      }, 35_000);
    });
  }
});

describe('fail-open: an unavailable store never breaks a hook', () => {
  // Non-header bytes → the first PRAGMA on open fails SQLITE_NOTADB, the
  // exact read failure the fail-open path guards against (mirrors
  // test/journey/harness.ts's corruptStore()).
  function seedCorruptStore(home: string): void {
    const storeDir = join(home, '.aka', 'data');
    mkdirSync(storeDir, { recursive: true });
    writeFileSync(
      join(storeDir, 'aka.db'),
      'AKA fail-open-e2e fixture — not a database\n'.repeat(64),
    );
  }

  // ~/.aka exists but is unwritable, so any mkdir/write under it (a fresh
  // data dir, settings.json, a throttle marker) hits EACCES.
  function seedReadOnlyAkaHome(home: string): void {
    const akaDir = join(home, '.aka');
    mkdirSync(akaDir, { recursive: true });
    chmodSync(akaDir, 0o555);
  }

  // chmod back before withTempHome's cleanup rmSync — a read-only dir can
  // block recursive removal of anything the hook wrote inside it before
  // hitting the fault.
  function restoreAkaHome(home: string): void {
    try {
      chmodSync(join(home, '.aka'), 0o755);
    } catch {
      // Nothing to restore.
    }
  }

  for (const hook of HOOKS) {
    describe(hook.name, () => {
      it('valid input, corrupt store → exit 0', () => {
        withTempHome((home) => {
          seedCorruptStore(home);
          const payload = hook.validPayload(home);
          const result = runHook(hook.name, payload, { env: tempHomeEnv(home) });
          expect(result.status).toBe(0);
          expectNoActionKey(result.stdout);
        });
      });

      it('valid input, read-only ~/.aka → exit 0', () => {
        withTempHome((home) => {
          seedReadOnlyAkaHome(home);
          try {
            const payload = hook.validPayload(home);
            const result = runHook(hook.name, payload, { env: tempHomeEnv(home) });
            expect(result.status).toBe(0);
            expectNoActionKey(result.stdout);
          } finally {
            restoreAkaHome(home);
          }
        });
      });
    });
  }
});

// ---------------------------------------------------------------------------
// The enforcement matrix: expectNoActionKey against real emitted payloads
// ---------------------------------------------------------------------------

// Every row above drives a hook that has NOTHING to say — malformed input, a
// store it cannot open — so every one of them asserts an empty stdout, and
// `expectNoActionKey` on `''` cannot fail. That left the wire-protocol pin
// covering none of the paths that actually build a payload: the shape it guards
// against is the internal decision object, and the internal decision object only
// exists once something was found.
//
// So this drives a real finding through each enforcing hook at each action level
// and reads what the built script really printed. The expected shape per cell is
// asserted first and is the positive control — without it, a hook that silently
// stopped emitting would turn every absence assertion below back into the
// vacuous form this section exists to replace.

// The value comes from a bundled rule's own `examples`, so no secret-shaped
// literal lives in this file. The rule is one whose example matches no OTHER
// bundled rule — two rules on overlapping spans degrade one-way and change the
// emitted shape, which would make the matrix a statement about rule overlap
// rather than about action levels.
const ENFORCED_RULE_ID = 'secrets/twilio-key';

function secretFixture(): { pack: ReturnType<typeof bundledDetections>[number]; example: string } {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === ENFORCED_RULE_ID));
  const example = pack?.rules.find((r) => r.id === ENFORCED_RULE_ID)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(
      `bundled rule ${ENFORCED_RULE_ID} is missing from the pack registry or has no example, so ` +
        'this matrix would drive clean input through every cell and assert nothing',
    );
  }
  return { pack, example };
}

const { pack: ENFORCED_PACK, example: SECRET } = secretFixture();

// Install the bundled packs the way the gateway does on open, then give the
// pack the policy under test — a per-pack policy is what the runtime's action
// resolution prefers, so this pins the cell to an action rather than to
// whatever DEFAULT_ACTIONS happens to say for the category.
function seedPolicy(home: string, policy: BuiltinPolicyId): void {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(ENFORCED_PACK.namespace, ENFORCED_PACK.packId, policy);
  } finally {
    db.close();
  }
}

interface EnforcingHook {
  readonly name: string;
  /** A payload whose scanned field carries the secret. */
  readonly payload: (home: string) => string;
  /**
   * The key the emitted JSON must carry per policy, or null where the hook
   * emits nothing at all. `monitor` is null for the two tool hooks because log
   * IS silence — CLAUDE.md §1's "allow is the absence of output", reached
   * through a finding rather than through a fault.
   */
  readonly emits: Readonly<Record<BuiltinPolicyId, string | null>>;
}

const ENFORCING_HOOKS: readonly EnforcingHook[] = [
  {
    name: 'user-prompt-submit',
    payload: (home) =>
      JSON.stringify({
        prompt: `deploy the service using ${SECRET}`,
        session_id: SESSION_ID,
        cwd: projectDir(home),
        hook_event_name: 'UserPromptSubmit',
      }),
    // Redact reads as block here: this hook cannot rewrite prompt text, so a
    // redact policy degrades to "remove it and resubmit" rather than tokenizing.
    // Monitor emits the calibration nudge — a systemMessage that is not an
    // enforcement opinion, and still a payload this pin has to read.
    emits: {
      block: '"decision":"block"',
      redact: '"decision":"block"',
      warn: '"systemMessage"',
      monitor: '"systemMessage"',
    },
  },
  {
    name: 'pre-tool-use',
    payload: (home) =>
      JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: `curl -H "authorization: ${SECRET}" https://example.invalid` },
        session_id: SESSION_ID,
        cwd: projectDir(home),
        hook_event_name: 'PreToolUse',
      }),
    // Redact denies rather than tokenizing because this home has no vault
    // consent: with the vault inert there is nowhere to put the value, and
    // one-way destruction of a tool call's input is not something to do quietly.
    emits: {
      block: '"permissionDecision":"deny"',
      redact: '"permissionDecision":"deny"',
      warn: '"systemMessage"',
      monitor: null,
    },
  },
  {
    name: 'post-tool-use',
    payload: (home) =>
      JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'cat .env' },
        tool_response: { stdout: `TWILIO_KEY=${SECRET}\n`, stderr: '' },
        session_id: SESSION_ID,
        cwd: projectDir(home),
        hook_event_name: 'PostToolUse',
      }),
    // Output is the model's to read, not the user's to resend, so both
    // enforcing levels rewrite it in place rather than refusing.
    emits: {
      block: '"updatedToolOutput"',
      redact: '"updatedToolOutput"',
      warn: '"systemMessage"',
      monitor: null,
    },
  },
];

const POLICIES: readonly BuiltinPolicyId[] = ['block', 'redact', 'warn', 'monitor'];

describe('the wire protocol never carries an action key, at any action level', () => {
  for (const hook of ENFORCING_HOOKS) {
    describe(hook.name, () => {
      for (const policy of POLICIES) {
        const expected = hook.emits[policy];
        it(`${policy} policy → ${expected === null ? 'emits nothing' : 'emits ' + expected}`, () => {
          withTempHome((home) => {
            seedPolicy(home, policy);
            const result = runHook(hook.name, hook.payload(home), { env: tempHomeEnv(home) });

            // Fail-open first: whatever it decided, it decided it without
            // breaking the session.
            expect(result.status).toBe(0);

            // The positive control. Everything after it is an absence, and an
            // absence over an unexpected payload — or none — proves nothing.
            if (expected === null) {
              expect(result.stdout).toBe('');
            } else {
              expect(result.stdout).toContain(expected);
            }

            expectNoActionKey(result.stdout);
            // The raw value never rides along on any of these shapes. Run by
            // run rather than whole: a branch echoing a truncated value is
            // still echoing a live credential's prefix.
            expectNoEchoOf(result.stdout, SECRET);
          });
        });
      }
    });
  }
});
