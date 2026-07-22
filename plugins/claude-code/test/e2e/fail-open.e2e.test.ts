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
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

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

// CLAUDE.md: "no hook ever emits {action:'allow'}, and the internal fallback
// is {action:'log'}" — `action` is a CaptureResult field that never crosses
// the wire; the four real hook-output shapes (`decision`, `systemMessage`,
// `hookSpecificOutput.permissionDecision`, `hookSpecificOutput.updatedToolOutput`)
// never use that key. Pinning this guards against a future refactor that
// starts serializing the internal decision object onto stdout.
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

      it(
        '100 MB stdin → exit 0, empty stdout, no OOM',
        () => {
          withTempHome((home) => {
            const result = runHook(hook.name, HUGE_STDIN, {
              env: tempHomeEnv(home),
              timeoutMs: 30_000,
            });
            expectFailsOpen(result.status, result.stdout);
          });
        },
        35_000,
      );
    });
  }
});
