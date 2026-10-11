import { expect, test } from 'claude-code/testing';

import { SESSION_CWD, fileSystem, helper, snapshotText } from './harness.js';
import type { Hooks, HelperReply } from './harness.js';
import { ACTION_OF, fill, RULE_IDS, SCENARIOS } from './scenarios.generated.js';
import { SECRET } from './samples.generated.js';

// The tool.call hook of the built mod, driven at `claude plugin test`'s seam. Two
// things sit beneath it, as they do in a session: the aka helper, answered the
// way the process would answer, and the end of the chain, which records the call
// the next layer (the PreToolUse command hook, then the tool) is handed.
//
// The table is the one the PreToolUse e2e test runs through the real helper and
// the real hook (test/e2e/mod-tool-call.e2e.test.ts), where each case's outcome
// is proven to be what the pipeline decides. Here the helper's answer is that
// outcome, and the assertion is what the mod does with it.

// Spelled by joining so no sensitive-looking literal sits in the source.
const POINTER = ['[[aka:secret:', 'AB.', 'A'.repeat(26), '.', 'B'.repeat(16), ']]'].join('');
const UNGRANTED = ['[[aka:secret:', 'AB.', 'C'.repeat(26), '.', 'D'.repeat(16), ']]'].join('');
const VALUES = {
  SECRET,
  IP: ['45', '79', '142', '6'].join('.'),
  EMAIL: ['user1', 'example.com'].join('@'),
  GRANTED: POINTER,
  UNGRANTED,
};

type Args = Record<string, unknown>;

// The end of the chain: what the next layer is handed, and the tool's answer.
function endOfChain(on: Hooks): Args[] {
  const seen: Args[] = [];
  on('tool.call', (_$, e) => {
    // The engine strips what it carries beside the arguments before the tool runs.
    const {
      tool: _tool,
      tool_use_id: _id,
      consent: _consent,
      agentId: _agent,
      ...args
    } = e as Args;
    seen.push(args);
    return { result: {}, text: 'ran' } as never;
  });
  return seen;
}

function snapshotFor(policy: Record<string, string>): string {
  const ruleActions: Record<string, string> = {};
  for (const [rule, archetype] of Object.entries(policy)) {
    ruleActions[RULE_IDS[rule]] = ACTION_OF[archetype];
  }
  return snapshotText({ ruleActions });
}

let stamp = 1000;
function useSnapshot(on: Hooks, policy: Record<string, string>): void {
  const text = snapshotFor(policy);
  stamp += 1;
  const mtimeMs = stamp;
  fileSystem(on, () => ({ text, mtimeMs }));
}

const ANSWER = (over: Partial<Record<string, unknown>> = {}): string =>
  JSON.stringify({ v: 1, deny: null, input: null, context: null, message: null, ...over });

for (const scenario of SCENARIOS) {
  test(`${scenario.tool}: ${scenario.name}`, async ($, on) => {
    useSnapshot(on, scenario.policy);
    const seen = endOfChain(on);
    const input: Args = fill(scenario.input, VALUES);
    const want = scenario.outcome;
    const stdout =
      want.kind === 'deny'
        ? ANSWER({ deny: fill(want.reasonIncludes, VALUES).join(' | ') })
        : want.kind === 'rewrite'
          ? ANSWER({ input: fill(want.input, VALUES) })
          : ANSWER();
    const asked = helper(on, { stdout });

    const result = await $.tool.call({ tool: scenario.tool, ...input } as never);

    // Only a call with something in it for the mod reaches the helper, and what
    // reaches it is the call's arguments and nothing the host added.
    expect(asked).toHaveLength(scenario.helper ? 1 : 0);
    if (scenario.helper) {
      expect(asked[0]?.argv[0]).toBe('node');
      expect(asked[0]?.argv[1]).toMatch(/[\\/]scripts[\\/]mod-tool-call\.js$/);
      expect(asked[0]?.timeoutMs).toBeLessThanOrEqual(3000);
      expect(asked[0]?.stdin).toMatchObject({ v: 1, tool: scenario.tool, input });
    }

    if (want.kind === 'deny') {
      for (const part of want.reasonIncludes) expect(result.deny).toContain(part);
      expect(seen).toEqual([]);
    } else {
      expect(result.deny).toBeUndefined();
      expect(seen).toEqual([want.kind === 'rewrite' ? fill(want.input, VALUES) : input]);
    }
  });
}

// The keys the host carries beside a call's arguments are not the tool's: `consent`
// (the words of the press that raised the call), `tool_use_id` and `agentId`. The
// helper decides the call the tool will run, and PreToolUse is shown that input,
// so the note the helper leaves is named by the arguments alone.
test('the reserved keys are never part of the input the helper decides', async ($, on) => {
  useSnapshot(on, {});
  const seen = endOfChain(on);
  const asked = helper(on, {
    stdout: ANSWER({ input: { command: 'deploy --token [REDACTED:SECRET]' } }),
  });

  const result = await $.tool.call({
    tool: 'Bash',
    tool_use_id: 'toolu_1',
    consent: 'The user pressed "1: Yes" on the grant',
    command: `deploy --token ${POINTER}`,
  } as never);

  expect(asked).toHaveLength(1);
  const sent = asked[0]?.stdin as unknown as { tool: string; input: Args };
  expect(sent.tool).toBe('Bash');
  expect(sent.input).toEqual({ command: `deploy --token ${POINTER}` });
  expect(JSON.stringify(asked[0]?.stdin)).not.toContain('pressed');
  expect(result.deny).toBeUndefined();
  expect(seen).toEqual([{ command: 'deploy --token [REDACTED:SECRET]' }]);
});

// A failure at any point leaves the call exactly as it came, to the layer beneath
// (the PreToolUse command hook), which denies an ungranted pointer in an executable
// field itself. The mod is never the only thing between the pointer and the shell.
const POINTER_CALL = { tool: 'Bash', command: `deploy --token ${UNGRANTED}` } as const;
const POINTER_ARGS = { command: `deploy --token ${UNGRANTED}` };

const FAILURES: [string, HelperReply][] = [
  ['the helper exits non-zero', { stdout: '', exitCode: 1 }],
  ['the helper is missing or times out', { deny: 'ETIMEDOUT' }],
  ['the helper prints nothing', { stdout: '' }],
  ['the helper prints something that is not JSON', { stdout: 'oops' }],
  ['the helper answers an unknown version', { stdout: ANSWER({ v: 2 }) }],
  ['the helper answers a deny with no reason', { stdout: ANSWER({ deny: '' }) }],
  [
    'the helper answers a deny and a rewrite together',
    { stdout: ANSWER({ deny: 'x', input: {} }) },
  ],
  ['the helper answers a rewrite that is not an object', { stdout: ANSWER({ input: 'x' }) }],
  ['the helper answers a context that is not text', { stdout: ANSWER({ context: 1 }) }],
];

for (const [name, reply] of FAILURES) {
  test(`fail-open: ${name}, so the call goes on unchanged for PreToolUse to deny`, async ($, on) => {
    useSnapshot(on, {});
    const seen = endOfChain(on);
    const asked = helper(on, reply);

    const result = await $.tool.call(POINTER_CALL as never);

    expect(asked).toHaveLength(1);
    expect(result.deny).toBeUndefined();
    expect(seen).toEqual([POINTER_ARGS]);
  });
}

test('fail-open: the engine throws, so the call goes on unchanged and the helper is not asked', async ($, on) => {
  useSnapshot(on, {});
  const seen = endOfChain(on);
  const asked = helper(on, { stdout: ANSWER({ deny: 'x' }) });
  const args = { command: `echo __ENGINE_THROWS__ ${UNGRANTED}` };

  const result = await $.tool.call({ tool: 'Bash', ...args } as never);

  expect(asked).toHaveLength(0);
  expect(result.deny).toBeUndefined();
  expect(seen).toEqual([args]);
});

test('fail-open: a corrupt policy snapshot does not stop a pointer reaching the helper', async ($, on) => {
  fileSystem(on, () => ({ text: '{"version":1,"ruleActions":', mtimeMs: 9001 }));
  const seen = endOfChain(on);
  const asked = helper(on, { stdout: ANSWER({ deny: 'a pointer cannot execute as text' }) });

  const result = await $.tool.call(POINTER_CALL as never);

  expect(asked).toHaveLength(1);
  expect(result.deny).toContain('cannot execute as text');
  expect(seen).toEqual([]);
});

test('a missing snapshot leaves a plain secret to the bundled defaults and the hook', async ($, on) => {
  fileSystem(on, () => undefined);
  const seen = endOfChain(on);
  const asked = helper(on, { stdout: ANSWER({ deny: 'x' }) });
  const args = { file_path: '/tmp/a.ts', content: `key = ${SECRET}` };

  const result = await $.tool.call({ tool: 'Write', ...args } as never);

  expect(asked).toHaveLength(0);
  expect(result.deny).toBeUndefined();
  expect(seen).toEqual([args]);
});

test('a tool with nothing to scan never reaches the helper', async ($, on) => {
  useSnapshot(on, { secret: 'redact' });
  const seen = endOfChain(on);
  const asked = helper(on, { stdout: ANSWER({ deny: 'x' }) });

  await $.tool.call({ tool: 'Read', file_path: '/tmp/a.ts' } as never);

  expect(asked).toHaveLength(0);
  expect(seen).toEqual([{ file_path: '/tmp/a.ts' }]);
});

test('the helper’s model note follows the tool’s result', async ($, on) => {
  useSnapshot(on, { email: 'redact' });
  endOfChain(on);
  helper(on, {
    stdout: ANSWER({
      input: { file_path: '/tmp/a.ts', content: 'support = [REDACTED:PII]' },
      context: '[AKA 0123456789abcdef] Write input: AKA replaced 1 value.',
    }),
  });

  const result = await $.tool.call({
    tool: 'Write',
    file_path: '/tmp/a.ts',
    content: `support = ${VALUES.EMAIL}`,
  } as never);

  expect(result.context).toEqual(['[AKA 0123456789abcdef] Write input: AKA replaced 1 value.']);
});

test('the helper is told the session cwd, and the cwd a call itself names wins', async ($, on) => {
  useSnapshot(on, {});
  endOfChain(on);
  const asked = helper(on, { stdout: ANSWER() });

  await $.tool.call({ tool: 'Bash', command: `deploy --token ${POINTER}` } as never);
  await $.tool.call({
    tool: 'Bash',
    command: `deploy --token ${POINTER}`,
    cwd: '/work/sub',
  } as never);

  expect(asked[0]?.stdin).toMatchObject({ cwd: SESSION_CWD });
  expect(asked[1]?.stdin).toMatchObject({ cwd: '/work/sub' });
});
