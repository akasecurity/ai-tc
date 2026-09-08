import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// The payloads under test/fixtures/cli/ are what Copilot CLI's hook loader wrote
// to each hook's stdin during one recorded session (the README beside them says
// what was rewritten before commit). Nothing else in the package reads them, so
// this suite is what notices a fixture being edited or the vendor's shape
// moving: it pins the fields the README describes, and it pins the SET of files,
// so a payload added without an assertion here fails rather than sitting unread.

const FIXTURE_DIR = fileURLToPath(new URL('./fixtures/cli/', import.meta.url));

const EVENTS = [
  'sessionStart',
  'userPromptSubmitted',
  'userPromptTransformed',
  'preToolUse',
  'permissionRequest',
  'postToolUse',
  'agentStop',
  'sessionEnd',
] as const;
type EventName = (typeof EVENTS)[number];

type Payload = Record<string, unknown>;

function readPayload(name: EventName): Payload {
  return JSON.parse(readFileSync(`${FIXTURE_DIR}${name}.json`, 'utf8')) as Payload;
}

// Read once: every case below compares fields ACROSS events (the same session
// id, the same tool args, timestamps in order), so they need one consistent set.
const payloads: Record<EventName, Payload> = {
  sessionStart: readPayload('sessionStart'),
  userPromptSubmitted: readPayload('userPromptSubmitted'),
  userPromptTransformed: readPayload('userPromptTransformed'),
  preToolUse: readPayload('preToolUse'),
  permissionRequest: readPayload('permissionRequest'),
  postToolUse: readPayload('postToolUse'),
  agentStop: readPayload('agentStop'),
  sessionEnd: readPayload('sessionEnd'),
};

function stringField(payload: Payload, key: string): string {
  const value = payload[key];
  expect(value, `${key} is a string`).toBeTypeOf('string');
  return value as string;
}

function objectField(payload: Payload, key: string): Payload {
  const value = payload[key];
  expect(value, `${key} is an object`).toBeTypeOf('object');
  expect(value, `${key} is not null`).not.toBeNull();
  expect(Array.isArray(value), `${key} is not an array`).toBe(false);
  return value as Payload;
}

function epochField(payload: Payload, key: string): number {
  const value = payload[key];
  expect(Number.isInteger(value), `${key} is an integer epoch`).toBe(true);
  expect(value as number).toBeGreaterThan(0);
  return value as number;
}

// Every path in the recordings was rewritten to this placeholder home before
// commit. Pinning the prefix is what keeps a re-recorded fixture from landing
// with a real home directory in it.
const PLACEHOLDER_HOME = '/Users/dev/';

describe('Copilot CLI hook payload fixtures', () => {
  it('are exactly the eight recorded events plus their README', () => {
    const expected = [...EVENTS.map((name) => `${name}.json`), 'README.md'].sort();
    expect(readdirSync(FIXTURE_DIR).sort()).toEqual(expected);
  });

  it('share one session id, an epoch timestamp and a placeholder cwd', () => {
    const sessionId = stringField(payloads.sessionStart, 'sessionId');
    expect(sessionId).toMatch(/^[0-9a-f-]{36}$/);
    for (const name of EVENTS) {
      expect(stringField(payloads[name], 'sessionId'), `${name}.sessionId`).toBe(sessionId);
      epochField(payloads[name], 'timestamp');
      expect(stringField(payloads[name], 'cwd'), `${name}.cwd`).toMatch(
        new RegExp(`^${PLACEHOLDER_HOME}`),
      );
    }
  });

  it('carry hookName on permissionRequest and on no other event', () => {
    expect(stringField(payloads.permissionRequest, 'hookName')).toBe('permissionRequest');
    for (const name of EVENTS) {
      if (name === 'permissionRequest') continue;
      expect(payloads[name], `${name} carries no hookName`).not.toHaveProperty('hookName');
    }
  });

  it('name the shell tool and its full arguments on preToolUse', () => {
    expect(stringField(payloads.preToolUse, 'toolName')).toBe('bash');
    const toolArgs = objectField(payloads.preToolUse, 'toolArgs');
    expect(stringField(toolArgs, 'command')).toBe('false');
    expect(Object.keys(toolArgs).sort()).toEqual(
      ['command', 'description', 'initial_wait', 'mode'].sort(),
    );
    expect(stringField(toolArgs, 'mode')).toBe('sync');
    expect(Number.isInteger(toolArgs.initial_wait)).toBe(true);
  });

  it('hand permissionRequest a strict subset of the preToolUse arguments', () => {
    expect(stringField(payloads.permissionRequest, 'toolName')).toBe(
      stringField(payloads.preToolUse, 'toolName'),
    );
    const toolArgs = objectField(payloads.preToolUse, 'toolArgs');
    const toolInput = objectField(payloads.permissionRequest, 'toolInput');
    // The subset is the property: `description` (model-authored), `mode` and
    // `initial_wait` reach a hook on preToolUse and nowhere else.
    expect(Object.keys(toolInput)).toEqual(['command']);
    for (const key of Object.keys(toolInput)) {
      expect(toolInput[key], `toolInput.${key} matches toolArgs`).toEqual(toolArgs[key]);
    }
    expect(Object.keys(toolArgs).length).toBeGreaterThan(Object.keys(toolInput).length);
    expect(Array.isArray(payloads.permissionRequest.permissionSuggestions)).toBe(true);
  });

  it('fire preToolUse, then permissionRequest, then postToolUse for one call', () => {
    const pre = epochField(payloads.preToolUse, 'timestamp');
    const permission = epochField(payloads.permissionRequest, 'timestamp');
    const post = epochField(payloads.postToolUse, 'timestamp');
    expect(pre).toBeLessThan(permission);
    expect(permission).toBeLessThan(post);
  });

  it('report a non-zero shell exit as a successful tool invocation', () => {
    // The command was `false`; the exit code is free text in the result and the
    // status field says the TOOL ran, which is the distinction a scanner has to
    // know before treating `resultType` as the command's outcome.
    expect(objectField(payloads.postToolUse, 'toolArgs')).toEqual(
      objectField(payloads.preToolUse, 'toolArgs'),
    );
    const toolResult = objectField(payloads.postToolUse, 'toolResult');
    expect(stringField(toolResult, 'resultType')).toBe('success');
    expect(stringField(toolResult, 'textResultForLlm')).toContain('exit code 1');
  });

  it('carry the transcript path on agentStop only, under the placeholder home', () => {
    const sessionId = stringField(payloads.agentStop, 'sessionId');
    const transcriptPath = stringField(payloads.agentStop, 'transcriptPath');
    expect(transcriptPath.startsWith(PLACEHOLDER_HOME)).toBe(true);
    expect(transcriptPath.endsWith(`/session-state/${sessionId}/events.jsonl`)).toBe(true);
    expect(payloads.sessionStart).not.toHaveProperty('transcriptPath');
    expect(stringField(payloads.agentStop, 'stopReason')).toBe('end_turn');
    expect(payloads.agentStop.stop_hook_active).toBeTypeOf('boolean');
  });

  it('carry the prompt through submit and transform, and the initial prompt on start', () => {
    const prompt = stringField(payloads.userPromptSubmitted, 'prompt');
    expect(prompt.length).toBeGreaterThan(0);
    expect(stringField(payloads.sessionStart, 'initialPrompt')).toBe(prompt);
    expect(stringField(payloads.sessionStart, 'source')).toBe('new');
    expect(stringField(payloads.userPromptTransformed, 'prompt')).toBe(prompt);
    const transformed = stringField(payloads.userPromptTransformed, 'transformedPrompt');
    expect(transformed).toContain(prompt);
    expect(transformed).not.toBe(prompt);
    expect(stringField(payloads.sessionEnd, 'reason')).toBe('complete');
  });
});
