// The pure pieces of the tool.call mod: the helper's answer, the handoff note and
// the engine's check for what is worth handing over. The helper and the hook are
// driven as processes in test/e2e/mod-tool-call.e2e.test.ts.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { exceptionPointer, REVEAL_DISCLOSURE_LEAD } from '../../src/exception-guidance.ts';
import { consumeToolHandoff, HANDOFF_TTL_MS, recordToolHandoff } from '../../src/mod/handoff.ts';
import { answerFromOutputs, messageForUser } from '../../src/mod/tool-call-answer.ts';
import { userDisclosure } from '../../src/protocol/notes.ts';

// The built engine, as the mod loads it (the source entry needs the build's
// generated rule data).
type NeedsHelper = (
  tool: string,
  input: Record<string, unknown>,
  policy: {
    rules: undefined;
    ruleActions: ReadonlyMap<string, 'redact' | 'block' | 'log' | 'warn'>;
    categoryActions: ReadonlyMap<string, 'log'>;
    exceptionRuleIds: ReadonlySet<string>;
  } | null,
) => boolean;
const ENGINE = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'hooks', 'engine.js');
const { toolCallNeedsHelper } = (await import(pathToFileURL(ENGINE).href)) as {
  toolCallNeedsHelper: NeedsHelper;
};

const POINTER = ['[[aka:secret:', 'AB.', 'A'.repeat(26), '.', 'B'.repeat(16), ']]'].join('');

describe('answerFromOutputs', () => {
  it('reads a deny as the call’s refusal and drops everything else', () => {
    const answer = answerFromOutputs([
      { systemMessage: 'noise' },
      {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: 'no',
        },
      },
    ]);
    expect(answer).toEqual({
      v: 1,
      deny: 'no',
      input: null,
      context: null,
      message: null,
      findings: [],
    });
  });

  it('reads an allow with updatedInput as the input to run, with its note and message', () => {
    const answer = answerFromOutputs([
      {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'allow',
          updatedInput: { content: 'x' },
          additionalContext: 'note',
        },
        systemMessage: 'AKA redacted',
      },
    ]);
    expect(answer).toEqual({
      v: 1,
      deny: null,
      input: { content: 'x' },
      context: 'note',
      message: 'AKA redacted',
      findings: [],
    });
  });

  it('reads a warning alone as a message and no change', () => {
    expect(answerFromOutputs([{ systemMessage: 'AKA flagged' }])).toEqual({
      v: 1,
      deny: null,
      input: null,
      context: null,
      message: 'AKA flagged',
      findings: [],
    });
  });

  it('reads nothing as no change', () => {
    expect(answerFromOutputs([])).toEqual({
      v: 1,
      deny: null,
      input: null,
      context: null,
      message: null,
      findings: [],
    });
  });
});

describe('messageForUser', () => {
  const summary = 'AKA redacted sensitive content in Write input — flagged secrets/x.';

  it('drops a summary the findings already show', () => {
    expect(messageForUser(summary, true)).toBeNull();
    expect(
      messageForUser(
        userDisclosure({
          surface: 'Write input',
          realized: { pointers: [{ token: POINTER, category: 'secret' }], degraded: [] },
        }),
        true,
      ),
    ).toBeNull();
  });

  it('keeps every message when there are no findings to show', () => {
    expect(messageForUser(summary, false)).toBe(summary);
    expect(messageForUser(null, false)).toBeNull();
    expect(messageForUser(null, true)).toBeNull();
  });

  it.each([
    [
      'a granted value revealed into the call',
      `${summary} ${REVEAL_DISCLOSURE_LEAD} to this Bash call.`,
    ],
    [
      'the command that allows a value',
      `${summary}${exceptionPointer([{ reference: 'abc123', ruleId: 'secrets/x', maskedValue: 'x***' }])}`,
    ],
    [
      'a value lost to an unavailable vault',
      userDisclosure({
        surface: 'Write input',
        realized: { pointers: [], degraded: [{ category: 'secret' }] },
      }) ?? '',
    ],
  ])('keeps the whole message when it carries %s', (_name, message) => {
    expect(messageForUser(message, true)).toBe(message);
  });
});

describe('tool handoff', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-tool-handoff-'));
  });
  afterEach(() => {
    removeTree(dir);
  });

  it('is consumed once, by the same tool and input', () => {
    recordToolHandoff(dir, 'Write', { file_path: '/a', content: 'x' });
    expect(consumeToolHandoff(dir, 'Write', { file_path: '/a', content: 'x' })).toBe(true);
    expect(consumeToolHandoff(dir, 'Write', { file_path: '/a', content: 'x' })).toBe(false);
  });

  it('does not depend on key order', () => {
    recordToolHandoff(dir, 'Write', { file_path: '/a', content: 'x' });
    expect(consumeToolHandoff(dir, 'Write', { content: 'x', file_path: '/a' })).toBe(true);
  });

  it('does not match another tool, another input or an expired note', () => {
    recordToolHandoff(dir, 'Write', { content: 'x' }, 1000);
    expect(consumeToolHandoff(dir, 'Edit', { content: 'x' }, 1001)).toBe(false);
    expect(consumeToolHandoff(dir, 'Write', { content: 'y' }, 1001)).toBe(false);
    expect(consumeToolHandoff(dir, 'Write', { content: 'x' }, 1000 + HANDOFF_TTL_MS)).toBe(false);
  });
});

describe('toolCallNeedsHelper', () => {
  const email = ['a', 'example.com'].join('@');
  const policy = (action: 'redact' | 'block' | 'log' | 'warn', excepted: string[] = []) => ({
    rules: undefined,
    ruleActions: new Map([['core-pii/email', action]]),
    categoryActions: new Map<string, 'log'>(),
    exceptionRuleIds: new Set(excepted),
  });

  it('hands over a pointer in a scanned field whatever the policy', () => {
    expect(toolCallNeedsHelper('Bash', { command: `x ${POINTER}` }, null)).toBe(true);
    expect(toolCallNeedsHelper('Write', { content: `x ${POINTER}` }, policy('log'))).toBe(true);
  });

  it('hands over a value its policy redacts or blocks, and not one it only logs or warns', () => {
    const input = { file_path: '/a', content: `mail ${email}` };
    expect(toolCallNeedsHelper('Write', input, policy('redact'))).toBe(true);
    expect(toolCallNeedsHelper('Write', input, policy('block'))).toBe(true);
    expect(toolCallNeedsHelper('Write', input, policy('warn'))).toBe(false);
    expect(toolCallNeedsHelper('Write', input, policy('log'))).toBe(false);
  });

  it('leaves a rule with an active exception to the hook', () => {
    const input = { file_path: '/a', content: `mail ${email}` };
    expect(toolCallNeedsHelper('Write', input, policy('redact', ['core-pii/email']))).toBe(false);
  });

  it('hands over nothing for a tool with no scanned field', () => {
    expect(toolCallNeedsHelper('Read', { file_path: '/a' }, policy('redact'))).toBe(false);
  });
});
