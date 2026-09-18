import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { detectDialect, readCwd, readSessionId, readToolCall } from '../../src/hooks/dialect.ts';

/** A recorded CLI payload, read from the fixture rather than retyped here. */
function cliFixture(event: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(new URL(`../fixtures/cli/${event}.json`, import.meta.url), 'utf8'),
  ) as Record<string, unknown>;
}

describe('detectDialect', () => {
  it('places every recorded CLI payload as cli', () => {
    // Driven from the recordings, so the sniff is held to eight real envelopes
    // rather than to one hand-written specimen. Every one of them carries
    // `sessionId` and none carries `hook_event_name`.
    for (const event of [
      'sessionStart',
      'sessionEnd',
      'userPromptSubmitted',
      'userPromptTransformed',
      'preToolUse',
      'postToolUse',
      'permissionRequest',
      'agentStop',
    ]) {
      expect(detectDialect(cliFixture(event)), event).toBe('cli');
    }
  });

  it('places a VS Code payload as vscode on hook_event_name', () => {
    expect(detectDialect({ hook_event_name: 'PreToolUse', session_id: 's' })).toBe('vscode');
  });

  it('places a VS Code payload carrying no session id at all', () => {
    // The reason the first rule is not redundant with the second: VS Code
    // documents `session_id` as sent ONLY WHEN KNOWN, so an early-session
    // payload can carry the event name and nothing else to key on.
    expect(detectDialect({ hook_event_name: 'SessionStart' })).toBe('vscode');
  });

  it('places a snake_case payload as vscode on session_id alone', () => {
    expect(detectDialect({ session_id: 's', tool_name: 'run_in_terminal' })).toBe('vscode');
  });

  it('lets hook_event_name win over a camelCase session id', () => {
    // A hybrid nobody has observed, ordered deliberately: `hook_event_name` is
    // the one field VS Code sends on every event, so it decides first. Pinned
    // so a reordering that let `sessionId` win is a failure rather than a
    // silent change of host.
    expect(detectDialect({ hook_event_name: 'PreToolUse', sessionId: 's' })).toBe('vscode');
  });

  it('answers undefined for an envelope matching neither dialect', () => {
    expect(detectDialect({ something: 'else' })).toBeUndefined();
  });

  it('answers undefined for anything that is not an object', () => {
    for (const value of [null, undefined, 'a string', 42, true, ['an', 'array']]) {
      expect(detectDialect(value)).toBeUndefined();
    }
  });

  it('ignores a session id that is not a string', () => {
    expect(detectDialect({ sessionId: 7 })).toBeUndefined();
    expect(detectDialect({ hook_event_name: 7, session_id: 7 })).toBeUndefined();
  });
});

describe('readSessionId', () => {
  it('reads the recorded CLI session id', () => {
    const input = cliFixture('preToolUse');
    expect(readSessionId('cli', input)).toBe('c1779e76-9889-419b-ab12-f7bb8a957e15');
  });

  it('reads the VS Code spelling', () => {
    expect(readSessionId('vscode', { session_id: 'abc' })).toBe('abc');
  });

  it('does not read the other dialect’s spelling', () => {
    // The discriminating pair. A reader that accepted both casings would place
    // a payload's id correctly by accident and hide a dialect misdetection.
    expect(readSessionId('cli', { session_id: 'abc' })).toBeUndefined();
    expect(readSessionId('vscode', { sessionId: 'abc' })).toBeUndefined();
  });

  it('treats an empty string as absent', () => {
    expect(readSessionId('cli', { sessionId: '' })).toBeUndefined();
  });
});

describe('readCwd', () => {
  it('reads the recorded CLI cwd', () => {
    expect(readCwd('cli', cliFixture('preToolUse'))).toBe('/Users/dev/ai-tc');
  });

  it('reads the same key under VS Code', () => {
    expect(readCwd('vscode', { cwd: '/w' })).toBe('/w');
  });

  it('answers undefined when VS Code omits it', () => {
    // VS Code sends `cwd` only when the hook entry declared one, and the
    // spawn's own cwd defaults to the HOME directory there — so absence has to
    // stay absence rather than falling back to something.
    expect(readCwd('vscode', { hook_event_name: 'PreToolUse' })).toBeUndefined();
  });
});

describe('readToolCall', () => {
  it('reads the recorded CLI tool call in full', () => {
    expect(readToolCall('cli', cliFixture('preToolUse'))).toEqual({
      name: 'bash',
      args: {
        command: 'false',
        description: 'Run the requested false command',
        mode: 'sync',
        initial_wait: 30,
      },
    });
  });

  it('reads permissionRequest’s strict subset of the same call', () => {
    // Recorded: `permissionRequest.toolInput` holds `command` only, while
    // `preToolUse.toolArgs` also holds `description`. The reader does not
    // reconcile them — that is the caller's problem, and the reason the scan
    // point is `preToolUse` — but the shape is pinned so the difference is
    // visible in the tree rather than only in the fixture README.
    const permission = cliFixture('permissionRequest');
    expect(permission.toolInput).toEqual({ command: 'false' });
    expect(Object.keys(cliFixture('preToolUse').toolArgs as object)).toContain('description');
  });

  it('reads the VS Code spelling', () => {
    expect(
      readToolCall('vscode', {
        hook_event_name: 'PreToolUse',
        tool_name: 'run_in_terminal',
        tool_input: { command: 'ls' },
      }),
    ).toEqual({ name: 'run_in_terminal', args: { command: 'ls' } });
  });

  it('does not read the other dialect’s spelling', () => {
    expect(readToolCall('cli', { tool_name: 'run_in_terminal' })).toBeUndefined();
    expect(readToolCall('vscode', { toolName: 'bash' })).toBeUndefined();
  });

  it('answers undefined when the call has no name', () => {
    expect(readToolCall('cli', { toolArgs: { command: 'ls' } })).toBeUndefined();
    expect(readToolCall('cli', { toolName: '' })).toBeUndefined();
  });

  it('reads a present name with no usable args as a call with no args', () => {
    // Deliberate: the NAME is what decides whether there is anything to scan.
    // A present name with a missing bag is a call with no scannable field, not
    // a broken envelope — and a `toolArgs` arriving as a JSON string (a shape
    // the card flags as possible and nobody has observed) reads the same way,
    // because guessing at an unobserved encoding would turn a shape this build
    // does not understand into a silent empty scan.
    expect(readToolCall('cli', { toolName: 'bash' })).toEqual({ name: 'bash', args: {} });
    expect(readToolCall('cli', { toolName: 'bash', toolArgs: '{"command":"ls"}' })).toEqual({
      name: 'bash',
      args: {},
    });
    expect(readToolCall('cli', { toolName: 'bash', toolArgs: ['ls'] })).toEqual({
      name: 'bash',
      args: {},
    });
  });
});
