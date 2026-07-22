/**
 * One smoke test per hook, proving the harness itself works: it spawns the
 * real built script, feeds it valid minimal input, and gets back a sane
 * {status, stdout, stderr}. This is NOT the fail-open matrix (malformed
 * input, corrupt store, …) — that's a separate, larger effort building on
 * this harness. Each run gets its own throwaway ~/.aka so nothing here ever
 * touches a developer's real store.
 */
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { runHook, tempHomeEnv, withTempHome } from './run-hook.ts';

// A hook's stdout is either empty (allow) or one JSON object — never
// malformed, regardless of which decision it made.
function expectValidHookStdout(stdout: string): void {
  if (stdout === '') return;
  expect(() => {
    JSON.parse(stdout);
  }).not.toThrow();
}

describe('runHook', () => {
  it('fails with a clear message when the target script has not been built', () => {
    expect(() => runHook('not-a-real-hook', '{}')).toThrow(/does not exist/);
  });

  it('SessionStart: runs against valid input and exits 0', () => {
    withTempHome((home) => {
      const cwd = join(home, 'project');
      mkdirSync(cwd, { recursive: true });
      const stdin = JSON.stringify({
        session_id: 'smoke-session',
        cwd,
        hook_event_name: 'SessionStart',
        source: 'startup',
      });

      const result = runHook('session-start', stdin, { env: tempHomeEnv(home) });

      expect(result.status).toBe(0);
      expectValidHookStdout(result.stdout);
    });
  });

  it('UserPromptSubmit: runs against valid input and exits 0', () => {
    withTempHome((home) => {
      const cwd = join(home, 'project');
      mkdirSync(cwd, { recursive: true });
      const stdin = JSON.stringify({
        prompt: 'hello from the smoke test',
        session_id: 'smoke-session',
        cwd,
        hook_event_name: 'UserPromptSubmit',
      });

      const result = runHook('user-prompt-submit', stdin, { env: tempHomeEnv(home) });

      expect(result.status).toBe(0);
      expectValidHookStdout(result.stdout);
    });
  });

  it('PreToolUse: runs against valid input and exits 0', () => {
    withTempHome((home) => {
      const cwd = join(home, 'project');
      mkdirSync(cwd, { recursive: true });
      const stdin = JSON.stringify({
        tool_name: 'Read',
        tool_input: { file_path: join(cwd, 'notes.txt') },
        session_id: 'smoke-session',
        cwd,
        hook_event_name: 'PreToolUse',
      });

      const result = runHook('pre-tool-use', stdin, { env: tempHomeEnv(home) });

      expect(result.status).toBe(0);
      expectValidHookStdout(result.stdout);
    });
  });

  it('PostToolUse: runs against valid input and exits 0', () => {
    withTempHome((home) => {
      const cwd = join(home, 'project');
      mkdirSync(cwd, { recursive: true });
      const stdin = JSON.stringify({
        tool_name: 'Read',
        tool_input: { file_path: join(cwd, 'notes.txt') },
        tool_response: { content: 'hello world' },
        session_id: 'smoke-session',
        cwd,
        hook_event_name: 'PostToolUse',
      });

      const result = runHook('post-tool-use', stdin, { env: tempHomeEnv(home) });

      expect(result.status).toBe(0);
      expectValidHookStdout(result.stdout);
    });
  });

  it('Stop: runs against valid input and exits 0', () => {
    withTempHome((home) => {
      const cwd = join(home, 'project');
      mkdirSync(cwd, { recursive: true });
      const stdin = JSON.stringify({
        session_id: 'smoke-session',
        transcript_path: join(cwd, 'transcript.jsonl'),
        cwd,
        hook_event_name: 'Stop',
        stop_hook_active: false,
      });

      const result = runHook('stop', stdin, { env: tempHomeEnv(home) });

      expect(result.status).toBe(0);
      expectValidHookStdout(result.stdout);
    });
  });
});
