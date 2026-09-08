import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// The payloads under test/fixtures/cli/ are what Copilot CLI's hook loader wrote
// to each hook's stdin during one recorded session (the README beside them says
// what was rewritten before commit). Nothing else in the package reads them, so
// this suite is what notices a fixture being edited or the vendor's shape
// moving: it pins the fields the README describes and the exact set of files.
// Where it pins something weaker than the README's prose — the transformed
// prompt's scaffolding is described but only its wrapping is asserted — the
// README says so rather than leaving the gap unstated.

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

// Which event a payload came from, so a helper failing inside a loop names the
// event rather than only the key. Without it a missing `sessionId` reports as
// "sessionId is a string" against the loop's own line, which locates nothing.
const EVENT_OF = new Map<Payload, string>(EVENTS.map((name) => [payloads[name], name]));
function scopeOf(source: Payload, label?: string): string {
  return label ?? EVENT_OF.get(source) ?? 'payload';
}

function stringField(source: Payload, key: string, label?: string): string {
  const value = source[key];
  expect(value, `${scopeOf(source, label)}.${key} is a string`).toBeTypeOf('string');
  return value as string;
}

function objectField(source: Payload, key: string, label?: string): Payload {
  const where = `${scopeOf(source, label)}.${key}`;
  const value = source[key];
  expect(value, `${where} is an object`).toBeTypeOf('object');
  expect(value, `${where} is not null`).not.toBeNull();
  expect(Array.isArray(value), `${where} is not an array`).toBe(false);
  return value as Payload;
}

function integerField(source: Payload, key: string, label?: string): number {
  const value = source[key];
  expect(Number.isInteger(value), `${scopeOf(source, label)}.${key} is an integer`).toBe(true);
  return value as number;
}

// Epoch MILLISECONDS, bounded rather than merely positive: a seconds-epoch or a
// placeholder like 1 satisfies "a positive integer" while being a different
// unit from the one the README documents and the ordering cases compare.
const MS_EPOCH_FLOOR = 1_700_000_000_000; // 2023-11
const MS_EPOCH_CEILING = 10_000_000_000_000; // 2286, the width of a 13-digit ms epoch
function epochField(source: Payload, key: string): number {
  const where = `${scopeOf(source)}.${key}`;
  const value = integerField(source, key);
  expect(value, `${where} is a millisecond epoch`).toBeGreaterThan(MS_EPOCH_FLOOR);
  expect(value, `${where} is a millisecond epoch`).toBeLessThan(MS_EPOCH_CEILING);
  return value;
}

// Every path in the recordings was rewritten to this placeholder home before
// commit. Pinning it is what keeps a re-recording from landing with a real home
// directory in it.
const PLACEHOLDER_HOME = '/Users/dev/';
// Any home-shaped path that is NOT under the placeholder. Scanned over the whole
// serialized payload rather than over the two fields that happen to hold a path
// today: a leaked home in `transformedPrompt` or in a tool result is the same
// defect and no field-by-field check would see it.
const FOREIGN_HOME = /\/(?:Users|home)\/(?!dev\/)/;

describe('Copilot CLI hook payload fixtures', () => {
  it('are exactly the eight recorded events plus their README', () => {
    // The count is pinned as well as the set: `expected` is derived from EVENTS,
    // so a ninth member would otherwise keep this green while the title said
    // eight. (A REMOVED fixture throws at module load instead of failing here.)
    expect(EVENTS).toHaveLength(8);
    const expected = [...EVENTS.map((name) => `${name}.json`), 'README.md'].sort();
    expect(readdirSync(FIXTURE_DIR).sort()).toEqual(expected);
  });

  it('share one session id, a millisecond timestamp and a placeholder cwd', () => {
    const sessionId = stringField(payloads.sessionStart, 'sessionId');
    expect(sessionId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    for (const name of EVENTS) {
      expect(stringField(payloads[name], 'sessionId'), `${name}.sessionId`).toBe(sessionId);
      epochField(payloads[name], 'timestamp');
      expect(stringField(payloads[name], 'cwd'), `${name}.cwd`).toBe(`${PLACEHOLDER_HOME}ai-tc`);
    }
  });

  it('carry no home-shaped path outside the placeholder, anywhere in the payload', () => {
    for (const name of EVENTS) {
      const serialized = JSON.stringify(payloads[name]);
      expect(FOREIGN_HOME.test(serialized), `${name} leaks a home directory`).toBe(false);
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
    const where = 'preToolUse.toolArgs';
    expect(stringField(toolArgs, 'command', where)).toBe('false');
    expect(Object.keys(toolArgs).sort()).toEqual(
      ['command', 'description', 'initial_wait', 'mode'].sort(),
    );
    // `description` is model-authored, so its presence as text is the property a
    // scanner depends on; the wording itself is the model's and is not pinned.
    expect(stringField(toolArgs, 'description', where).length).toBeGreaterThan(0);
    expect(stringField(toolArgs, 'mode', where)).toBe('sync');
    expect(integerField(toolArgs, 'initial_wait', where)).toBe(30);
  });

  it('hand permissionRequest a strict subset of the preToolUse arguments', () => {
    expect(stringField(payloads.permissionRequest, 'toolName')).toBe(
      stringField(payloads.preToolUse, 'toolName'),
    );
    const toolArgs = objectField(payloads.preToolUse, 'toolArgs');
    const toolInput = objectField(payloads.permissionRequest, 'toolInput');
    // The subset is the property: `description` (model-authored), `mode` and
    // `initial_wait` reach a hook on preToolUse and postToolUse, never here.
    expect(Object.keys(toolInput)).toEqual(['command']);
    for (const key of Object.keys(toolInput)) {
      expect(toolInput[key], `toolInput.${key} matches toolArgs`).toEqual(toolArgs[key]);
    }
    expect(Object.keys(toolArgs).length).toBeGreaterThan(Object.keys(toolInput).length);
  });

  it('record permissionSuggestions empty, as the session ran under --allow-all', () => {
    // Recorded EMPTY, and `--allow-all` is the likely reason: nothing was left
    // to suggest. Pinned as the value seen rather than as "an array", so a
    // re-recording that shows the populated shape has to say what it found.
    expect(payloads.permissionRequest.permissionSuggestions).toEqual([]);
  });

  it('fire the prompt events BEFORE sessionStart, then the tool call, in one recorded order', () => {
    // The whole order, not a pair: the session's own start event is stamped 20ms
    // AFTER the prompt that started it, so a once-per-session pass hung off
    // sessionStart runs when that prompt has already been submitted and
    // transformed. Pinning only preToolUse < permissionRequest < postToolUse
    // left that invisible.
    const stamps = EVENTS.map((name) => [name, epochField(payloads[name], 'timestamp')] as const);
    const recorded = [...stamps].sort((a, b) => a[1] - b[1]).map(([name]) => name);
    expect(recorded).toEqual([
      'userPromptSubmitted',
      'userPromptTransformed',
      'sessionStart',
      'preToolUse',
      'permissionRequest',
      'postToolUse',
      'agentStop',
      'sessionEnd',
    ]);
  });

  it('repeat one call across preToolUse, permissionRequest and postToolUse', () => {
    // Same tool, same arguments: postToolUse re-delivers `toolArgs` in full
    // (permissionRequest does not — see the subset case above), which is what
    // makes `description` reachable after the call as well as before it.
    expect(stringField(payloads.postToolUse, 'toolName')).toBe(
      stringField(payloads.preToolUse, 'toolName'),
    );
    expect(objectField(payloads.postToolUse, 'toolArgs')).toEqual(
      objectField(payloads.preToolUse, 'toolArgs'),
    );
  });

  it('report a non-zero shell exit as a successful tool invocation', () => {
    // The command was `false`; the exit code is free text in the result and the
    // status field says the TOOL ran, which is the distinction a scanner has to
    // know before treating `resultType` as the command's outcome. The text
    // begins with a newline, so a `^<shellId` anchor would miss it.
    const toolResult = objectField(payloads.postToolUse, 'toolResult');
    const where = 'postToolUse.toolResult';
    expect(stringField(toolResult, 'resultType', where)).toBe('success');
    expect(stringField(toolResult, 'textResultForLlm', where)).toBe(
      '\n<shellId: 0 completed with exit code 1>',
    );
  });

  it('carry the transcript path on agentStop only, under the placeholder home', () => {
    const sessionId = stringField(payloads.agentStop, 'sessionId');
    // The exact sanitized value, which is what the README documents — including
    // the `.copilot` segment a prefix-and-suffix check would not reach.
    expect(stringField(payloads.agentStop, 'transcriptPath')).toBe(
      `${PLACEHOLDER_HOME}.copilot/session-state/${sessionId}/events.jsonl`,
    );
    // "Only" is the claim, so every other event is checked, the way hookName is.
    for (const name of EVENTS) {
      if (name === 'agentStop') continue;
      expect(payloads[name], `${name} carries no transcriptPath`).not.toHaveProperty(
        'transcriptPath',
      );
    }
  });

  it('mark the session lifecycle: a new start, an end_turn stop, a complete end', () => {
    expect(stringField(payloads.sessionStart, 'source')).toBe('new');
    expect(stringField(payloads.agentStop, 'stopReason')).toBe('end_turn');
    // The recorded value, not merely "a boolean" — the same reason the empty
    // permissionSuggestions is pinned as the value seen.
    expect(payloads.agentStop.stop_hook_active).toBe(false);
    expect(stringField(payloads.sessionEnd, 'reason')).toBe('complete');
  });

  it('carry the prompt on submit, on transform and as the session initial prompt', () => {
    const prompt = stringField(payloads.userPromptSubmitted, 'prompt');
    expect(prompt.length).toBeGreaterThan(0);
    expect(stringField(payloads.sessionStart, 'initialPrompt')).toBe(prompt);
    // userPromptTransformed re-carries the untransformed prompt beside the
    // wrapped one. The scaffolding's own content is the CLI's and is described
    // in the README rather than pinned here.
    expect(stringField(payloads.userPromptTransformed, 'prompt')).toBe(prompt);
    const transformed = stringField(payloads.userPromptTransformed, 'transformedPrompt');
    expect(transformed).toContain(prompt);
    expect(transformed).not.toBe(prompt);
  });
});
