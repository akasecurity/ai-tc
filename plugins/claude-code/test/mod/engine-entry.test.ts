// The engine module's source (src/mod/engine-entry.ts), driven in-process so its
// lines are measured; the built hooks/engine.js is covered by the parity tests.
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import {
  bundledActionFor,
  createPromptPlanner,
  createReplySlots,
  type ModPolicy,
  parseModPolicy,
  planPromptWith,
  planRowWith,
  redactPrompt,
  redactPromptWith,
  registerBundledPacks,
  revealPointers,
  revealSlots,
  toolCallNeedsHelper,
} from '../../src/mod/engine-entry.ts';

const RULE_ID = 'secrets/twilio-key';
const rules = bundledDetections().flatMap((p) => p.rules);
const SECRET = rules.find((r) => r.id === RULE_ID)?.examples?.[0] ?? '';
const POINTER = ['[[aka:secret:', 'AB.', 'A'.repeat(26), '.', 'B'.repeat(16), ']]'].join('');
const POINTER_2 = ['[[aka:secret:', 'AB.', 'C'.repeat(26), '.', 'D'.repeat(16), ']]'].join('');

function policy(over: Partial<ModPolicy> = {}): ModPolicy {
  return {
    rules: undefined,
    ruleActions: new Map([[RULE_ID, 'redact']]),
    categoryActions: new Map(),
    exceptionRuleIds: new Set(),
    ...over,
  };
}

describe('parseModPolicy', () => {
  const good = {
    version: 1,
    ruleActions: { [RULE_ID]: 'redact' },
    categoryActions: { secret: 'warn' },
    exceptionRuleIds: ['x'],
  };
  const parse = (v: unknown): ModPolicy | null => parseModPolicy(JSON.stringify(v));

  it('reads a snapshot into lookups', () => {
    const p = parse(good);
    expect(p?.ruleActions.get(RULE_ID)).toBe('redact');
    expect(p?.categoryActions.get('secret')).toBe('warn');
    expect(p?.exceptionRuleIds.has('x')).toBe(true);
    expect(p?.rules).toBeUndefined();
  });

  it('keeps a usable ruleset', () => {
    const p = parse({ ...good, rules: [{ id: 'a', category: 'c', matcher: { type: 'regex' } }] });
    expect(p?.rules).toHaveLength(1);
  });

  it.each([
    ['not json', '{'],
    ['an array', '[]'],
    ['another version', JSON.stringify({ ...good, version: 2 })],
    ['a bad rule action', JSON.stringify({ ...good, ruleActions: { a: 'nope' } })],
    ['a non-string action', JSON.stringify({ ...good, ruleActions: { a: 1 } })],
    ['no rule actions', JSON.stringify({ ...good, ruleActions: [] })],
    ['bad exceptions', JSON.stringify({ ...good, exceptionRuleIds: [1] })],
    ['missing exceptions', JSON.stringify({ ...good, exceptionRuleIds: undefined })],
    ['rules that are not an array', JSON.stringify({ ...good, rules: {} })],
    ['a rule without a matcher', JSON.stringify({ ...good, rules: [{ id: 'a', category: 'c' }] })],
  ])('refuses %s', (_name, text) => {
    expect(parseModPolicy(text)).toBeNull();
  });
});

describe('prompt planning', () => {
  it('knows the bundled actions, and logs a rule it does not know', () => {
    expect(bundledActionFor('no/such-rule')).toBe('log');
    registerBundledPacks();
    expect(bundledActionFor(RULE_ID)).toBeTypeOf('string');
  });

  it('redacts nothing under the bundled defaults', () => {
    const text = `key ${SECRET}`;
    expect(redactPrompt(text)).toBe(text);
  });

  it('rewrites a redact finding and reports the value it removed', () => {
    const plan = planPromptWith(`key ${SECRET} now`, policy());
    expect(plan.text).toBe('key [REDACTED:SECRET] now');
    expect(plan.values).toEqual([SECRET]);
    expect(redactPromptWith(`key ${SECRET}`, policy())).toBe('key [REDACTED:SECRET]');
  });

  it('falls back to the category action, then to log', () => {
    const byCategory = policy({
      ruleActions: new Map(),
      categoryActions: new Map([['secret', 'redact']]),
    });
    expect(planPromptWith(`key ${SECRET}`, byCategory).text).toContain('[REDACTED:');
    const none = policy({ ruleActions: new Map() });
    expect(planPromptWith(`key ${SECRET}`, none).values).toEqual([]);
  });

  it('leaves a prompt holding a block, and a rule with an exception, untouched', () => {
    const text = `key ${SECRET}`;
    expect(planPromptWith(text, policy({ ruleActions: new Map([[RULE_ID, 'block']]) })).text).toBe(
      text,
    );
    expect(planPromptWith(text, policy({ exceptionRuleIds: new Set([RULE_ID]) })).values).toEqual(
      [],
    );
  });

  it('does not re-tokenize a pointer, and plans a row as a response', () => {
    expect(planPromptWith(`see ${POINTER}`, policy()).values).toEqual([]);
    expect(planRowWith(`key ${SECRET}`, policy()).values).toEqual([SECRET]);
    expect(planRowWith(`key ${SECRET}`, null).values).toEqual([]);
    const byCategory = policy({
      ruleActions: new Map(),
      categoryActions: new Map([['secret', 'redact']]),
    });
    expect(planRowWith(`key ${SECRET}`, byCategory).values).toEqual([SECRET]);
  });

  it('uses a policy ruleset instead of the bundled packs', () => {
    const own = rules.filter((r) => r.id === RULE_ID);
    expect(own).toHaveLength(1);
    const plan = createPromptPlanner(() => 'redact', { rules: own })(`key ${SECRET}`);
    expect(plan.values).toEqual([SECRET]);
  });
});

describe('revealing pointers', () => {
  it('grants the first cap distinct pointers a slot, and never changes an answer', () => {
    const slot = revealSlots(1);
    expect(slot(POINTER)).toBe(true);
    expect(slot(POINTER)).toBe(true);
    expect(slot(POINTER_2)).toBe(false);
    expect(slot(POINTER_2)).toBe(false);
    expect(revealSlots()(POINTER)).toBe(true);
  });

  it('swaps what draw answers, shields code and quotes, and lists what it could not answer', () => {
    const draw = (want: { token: string; shielded: boolean }) =>
      want.token === POINTER ? { text: want.shielded ? 'MASKED' : 'VALUE', revealed: true } : null;
    const out = revealPointers(
      `a ${POINTER} b\n\`${POINTER}\` c ${POINTER_2}\n> ${POINTER}\n\`\`\`\n${POINTER}\n\`\`\`\n`,
      draw,
      () => true,
    );
    expect(out.text).toContain('a VALUE b');
    expect(out.text).toContain('`MASKED`');
    expect(out.text).toContain('> MASKED');
    expect(out.wanted.map((w) => w.token)).toEqual([POINTER_2]);
    const refused = revealPointers(POINTER, draw, () => false);
    expect(refused.text).toBe('MASKED');
  });

  it('groups the blocks of a reply under one cap', () => {
    const slotsFor = createReplySlots();
    const first = slotsFor({ component: 'AssistantMessage', requestId: 'a', isFirstOfReply: true });
    const joined = slotsFor({
      component: 'AssistantMessage',
      requestId: 'b',
      isFirstOfReply: false,
    });
    expect(joined).toBe(first);
    expect(slotsFor({ component: 'AssistantMessage', requestId: 'a', isFirstOfReply: true })).toBe(
      first,
    );
    // a known block keeps its reply even when a later one opened another
    const second = slotsFor({
      component: 'AssistantMessage',
      requestId: 'c',
      isFirstOfReply: true,
    });
    expect(second).not.toBe(first);
    expect(slotsFor({ component: 'AssistantMessage', requestId: 'b', isFirstOfReply: false })).toBe(
      first,
    );
    // a non-assistant block is its own reply
    const user = slotsFor({ component: 'UserMessage', requestId: 'd', isFirstOfReply: false });
    expect(user).not.toBe(second);
  });

  it('opens a reply for a joining block when none is open, and forgets the oldest past its bound', () => {
    const slotsFor = createReplySlots(2, 2);
    const orphan = slotsFor({
      component: 'AssistantMessage',
      requestId: 'x',
      isFirstOfReply: false,
    });
    expect(orphan(POINTER)).toBe(true);
    slotsFor({ component: 'AssistantMessage', requestId: 'y', isFirstOfReply: true });
    slotsFor({ component: 'AssistantMessage', requestId: 'z', isFirstOfReply: true });
    // 'x' was forgotten: met again, it is a new reply
    expect(
      slotsFor({ component: 'AssistantMessage', requestId: 'x', isFirstOfReply: true }),
    ).not.toBe(orphan);
  });
});

describe('toolCallNeedsHelper', () => {
  it('is false for a tool with nothing scanned or an empty field', () => {
    expect(toolCallNeedsHelper('NoSuchTool', { a: 1 }, null)).toBe(false);
    expect(toolCallNeedsHelper('Bash', { command: '' }, null)).toBe(false);
    expect(toolCallNeedsHelper('Bash', {}, null)).toBe(false);
  });

  it('is true for a pointer, and for a value the policy redacts or blocks', () => {
    expect(toolCallNeedsHelper('Bash', { command: `run ${POINTER}` }, null)).toBe(true);
    expect(toolCallNeedsHelper('Bash', { command: `run ${SECRET}` }, policy())).toBe(true);
    const block = policy({ ruleActions: new Map([[RULE_ID, 'block']]) });
    expect(toolCallNeedsHelper('Write', { file_path: '/a.txt', content: SECRET }, block)).toBe(
      true,
    );
  });

  it('is false for a value only logged, bundled defaults, or an excepted rule', () => {
    expect(toolCallNeedsHelper('Bash', { command: `run ${SECRET}` }, null)).toBe(false);
    expect(
      toolCallNeedsHelper('Bash', { command: `run ${SECRET}` }, policy({ ruleActions: new Map() })),
    ).toBe(false);
    expect(
      toolCallNeedsHelper(
        'Bash',
        { command: `run ${SECRET}` },
        policy({ exceptionRuleIds: new Set([RULE_ID]) }),
      ),
    ).toBe(false);
  });
});
