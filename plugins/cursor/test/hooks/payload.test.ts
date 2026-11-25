import { describe, expect, it } from 'vitest';

import { CURSOR_EVENTS, isOwnEvent, readEventName } from '../../src/hooks/event-name.ts';
import { readCwd, readPayloadEvent, readSessionId, readToolCall } from '../../src/hooks/payload.ts';
import { payload } from '../helpers/store.ts';

describe('readSessionId', () => {
  it('reads session_id first, then conversation_id', () => {
    expect(readSessionId({ session_id: 's', conversation_id: 'c' })).toBe('s');
    expect(readSessionId({ conversation_id: 'c' })).toBe('c');
    expect(readSessionId({ session_id: '', conversation_id: 'c' })).toBe('c');
    expect(readSessionId({})).toBeUndefined();
  });

  it('gives every constructed payload the same session', () => {
    const ids = ['sessionStart', 'beforeSubmitPrompt', 'preToolUse', 'postToolUse'].map((e) =>
      readSessionId(payload(e)),
    );
    expect(new Set(ids).size).toBe(1);
    expect(ids[0]).toBeDefined();
  });
});

describe('readCwd', () => {
  it('prefers cwd, then the first workspace root', () => {
    expect(readCwd({ cwd: '/a', workspace_roots: ['/b'] })).toBe('/a');
    expect(readCwd({ workspace_roots: ['/b', '/c'] })).toBe('/b');
  });

  it('answers undefined rather than guessing', () => {
    expect(readCwd({})).toBeUndefined();
    expect(readCwd({ workspace_roots: [] })).toBeUndefined();
    expect(readCwd({ workspace_roots: [42] })).toBeUndefined();
    expect(readCwd({ workspace_roots: '/b' })).toBeUndefined();
  });
});

describe('readToolCall', () => {
  it('reads an object tool_input', () => {
    expect(readToolCall({ tool_name: 'Shell', tool_input: { command: 'ls' } })).toEqual({
      name: 'Shell',
      args: { command: 'ls' },
    });
  });

  it('parses a JSON-string tool_input that holds an object', () => {
    expect(readToolCall({ tool_name: 'Shell', tool_input: '{"command":"ls"}' })?.args).toEqual({
      command: 'ls',
    });
  });

  it('reads any other tool_input as no args', () => {
    for (const raw of ['ls', '[1]', 42, null, undefined, ['x']]) {
      expect(readToolCall({ tool_name: 'Shell', tool_input: raw })?.args).toEqual({});
    }
  });

  it('answers undefined with no tool name', () => {
    expect(readToolCall({ tool_input: { command: 'ls' } })).toBeUndefined();
  });
});

describe('event names', () => {
  it('reads a known token from argv[2] only', () => {
    expect(readEventName(['node', 'script', 'preToolUse'])).toBe('preToolUse');
    expect(readEventName(['node', 'script', 'PreToolUse'])).toBeUndefined();
    expect(readEventName(['node', 'script'])).toBeUndefined();
  });

  it('names every event the constructed payloads carry', () => {
    for (const event of ['sessionStart', 'beforeSubmitPrompt', 'preToolUse', 'postToolUse']) {
      expect(CURSOR_EVENTS).toContain(readPayloadEvent(payload(event)));
    }
  });

  it('declines when either source names another event', () => {
    expect(isOwnEvent('preToolUse', undefined, undefined)).toBe(true);
    expect(isOwnEvent('preToolUse', 'preToolUse', 'preToolUse')).toBe(true);
    expect(isOwnEvent('preToolUse', 'postToolUse', undefined)).toBe(false);
    expect(isOwnEvent('preToolUse', undefined, 'postToolUse')).toBe(false);
  });
});
