// `detectDialect` decides which host's field names everything downstream
// reads. Getting it wrong is not a crash: it is a scan that runs, finds
// nothing, and reports success — so every branch is pinned, including the one
// that declines to answer.
//
// The CLI cases are driven from the LIVE RECORDINGS rather than from
// hand-written objects. A hand-written envelope is a restatement of the
// detector's own assumptions and cannot falsify them.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { detectDialect, readCwd, readSessionId, readToolCall } from '../../src/hooks/dialect.ts';

const FIXTURES = fileURLToPath(new URL('../fixtures/cli/', import.meta.url));

const recording = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), 'utf8')) as Record<string, unknown>;

describe('detectDialect', () => {
  it('answers cli for every recorded CLI payload', () => {
    const files = readdirSync(FIXTURES).filter((n) => n.endsWith('.json'));
    // Positive control on the derivation: an empty directory would satisfy the
    // loop below while asserting nothing.
    expect(files.length).toBeGreaterThan(1);
    for (const name of files) {
      const payload = JSON.parse(readFileSync(join(FIXTURES, name), 'utf8')) as Record<
        string,
        unknown
      >;
      expect(detectDialect(payload), name).toBe('cli');
    }
  });

  it('answers vscode on hook_event_name, which that host sends on every event', () => {
    expect(detectDialect({ hook_event_name: 'PreToolUse' })).toBe('vscode');
  });

  it('prefers hook_event_name over the session key', () => {
    // The ordering matters and is not arbitrary. A VS Code payload carrying a
    // `sessionId` key for any reason must still be read as VS Code, because
    // `hook_event_name` is the field that is total over that host.
    expect(detectDialect({ hook_event_name: 'PreToolUse', sessionId: 'x' })).toBe('vscode');
  });

  it('falls back to the session key casing', () => {
    expect(detectDialect({ sessionId: 'a' })).toBe('cli');
    expect(detectDialect({ session_id: 'a' })).toBe('vscode');
  });

  it('declines to answer for an envelope matching neither', () => {
    // The branch that stops a wrong guess. A payload with no recognisable
    // envelope is handed no dialect, and the caller turns that into an explicit
    // allow rather than into a scan of the wrong field names.
    expect(detectDialect({})).toBeUndefined();
    expect(detectDialect({ tool_name: 'run_in_terminal' })).toBeUndefined();
    expect(detectDialect({ toolName: 'bash' })).toBeUndefined();
    // A non-string value is not a signal: every one of these keys is a string
    // on both hosts.
    expect(detectDialect({ sessionId: 7 })).toBeUndefined();
    expect(detectDialect({ hook_event_name: null })).toBeUndefined();
  });
});

describe('readToolCall', () => {
  it('reads the recorded CLI bash call under the CLI key names', () => {
    const call = readToolCall(recording('preToolUse'), 'cli');
    expect(call?.name).toBe('bash');
    expect(call?.args.command).toBe('false');
    // `description` is model-authored prose riding alongside the command, and
    // it is the field a redact can actually be carried out on.
    expect(typeof call?.args.description).toBe('string');
  });

  it('reads a VS Code call under the VS Code key names', () => {
    const call = readToolCall(
      { tool_name: 'run_in_terminal', tool_input: { command: 'ls' } },
      'vscode',
    );
    expect(call).toEqual({ name: 'run_in_terminal', args: { command: 'ls' } });
  });

  it('returns undefined when the OTHER dialect’s keys are used', () => {
    // The failure this whole module exists to prevent, driven directly: a real
    // CLI payload read as VS Code must answer "no tool call" rather than
    // answering a call with no arguments, which would scan nothing and report
    // success.
    expect(readToolCall(recording('preToolUse'), 'vscode')).toBeUndefined();
    expect(readToolCall({ tool_name: 'run_in_terminal', tool_input: {} }, 'cli')).toBeUndefined();
  });

  it('returns undefined for a missing or empty tool name', () => {
    expect(readToolCall({ toolArgs: { command: 'x' } }, 'cli')).toBeUndefined();
    expect(readToolCall({ toolName: '', toolArgs: {} }, 'cli')).toBeUndefined();
    expect(readToolCall({ toolName: 7 }, 'cli')).toBeUndefined();
  });

  it('gives an empty args bag rather than undefined when the args are absent', () => {
    // A named call with no arguments is a real thing to have an opinion about;
    // there is simply nothing in it to scan. A call with no NAME is one no
    // field table can be looked up for, which is why only that one declines.
    expect(readToolCall({ toolName: 'bash' }, 'cli')).toEqual({ name: 'bash', args: {} });
    expect(readToolCall({ toolName: 'bash', toolArgs: 'nope' }, 'cli')).toEqual({
      name: 'bash',
      args: {},
    });
    expect(readToolCall({ toolName: 'bash', toolArgs: null }, 'cli')).toEqual({
      name: 'bash',
      args: {},
    });
  });
});

describe('readSessionId / readCwd', () => {
  it('reads the recorded CLI envelope', () => {
    const payload = recording('preToolUse');
    expect(readSessionId(payload, 'cli')).toBe('c1779e76-9889-419b-ab12-f7bb8a957e15');
    expect(readCwd(payload, 'cli')).toBe('/Users/dev/ai-tc');
  });

  it('reads the VS Code envelope, and tolerates the cwd that host may omit', () => {
    // VS Code sends `cwd` only when the hook's own entry declared one; its
    // spawn cwd otherwise defaults to the HOME directory, which is not the
    // workspace. Absent is therefore a normal reading on that host, not a
    // malformed payload.
    expect(readSessionId({ session_id: 's1' }, 'vscode')).toBe('s1');
    expect(readCwd({ session_id: 's1' }, 'vscode')).toBeUndefined();
    expect(readCwd({ session_id: 's1', cwd: '/w' }, 'vscode')).toBe('/w');
  });

  it('does not read the other dialect’s session key', () => {
    expect(readSessionId({ sessionId: 'a' }, 'vscode')).toBeUndefined();
    expect(readSessionId({ session_id: 'a' }, 'cli')).toBeUndefined();
  });
});
