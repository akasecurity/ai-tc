import { expect, mock, test } from 'claude-code/testing';
import type { SessionAppendInput } from 'claude-code';

import { fileSystem, helper, snapshotText } from './harness.js';
import type { Hooks } from './harness.js';
import { SECRET } from './samples.generated.js';

// The tool-result door at the seam. PostToolUse runs first for the same call, so
// the row may already hold pointers or one-way markers; only a value it left raw
// is rewritten here. The helper and the store are answered from beneath.

// Spelled by joining so no pointer-shaped literal sits in the source.
const POINTER = ['[[aka:secret:', 'AB.', 'A'.repeat(26), '.', 'B'.repeat(16), ']]'].join('');
const ONE_WAY = ['[REDACTED', ':SECRET]'].join('');

let nextId = 400;
function redactSecrets(on: Hooks): void {
  nextId += 1;
  fileSystem(on, () => ({
    text: snapshotText({ categoryActions: { secret: 'redact' } }),
    mtimeMs: nextId,
  }));
}

function pointerReply(request: { stdin: { text: string } }): string {
  return JSON.stringify({ v: 1, text: request.stdin.text.replaceAll(SECRET, POINTER), note: null });
}

type Content = SessionAppendInput['message']['content'];

function resultRow(content: Content, extra: Partial<SessionAppendInput> = {}): SessionAppendInput {
  return {
    message: { type: 'user', role: 'user', content },
    door: 'tool-result',
    origin: { kind: 'tool', tool: 'Read' },
    uuid: 'row-tool-result',
    ...extra,
  };
}

const asString = (text: string): Content => [
  { type: 'tool_result', tool_use_id: 'toolu_1', content: text },
];
const asBlocks = (...texts: string[]): Content => [
  {
    type: 'tool_result',
    tool_use_id: 'toolu_1',
    content: texts.map((text) => ({ type: 'text', text })),
  },
];

const store = (on: Hooks): (() => readonly SessionAppendInput[]) => mock.session(on).appended;

for (const tool of ['Read', 'Grep', 'Glob', 'Bash', 'WebFetch', 'mcp__files__read']) {
  test(`a secret in ${tool} output reaches the model only as a pointer`, async ($, on) => {
    redactSecrets(on);
    const appended = store(on);
    const asked = helper(on, pointerReply);

    await $.session.append(
      resultRow(asString(`line 1\nkey=${SECRET}\nline 3`), { origin: { kind: 'tool', tool } }),
    );

    expect(appended()[0]?.message.content).toEqual(asString(`line 1\nkey=${POINTER}\nline 3`));
    expect(asked).toHaveLength(1);
    expect(asked[0]?.stdin.row).toEqual({ door: 'tool-result' });
  });
}

test('output held as content blocks is rewritten block by block, others kept', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  helper(on, pointerReply);
  const image = {
    type: 'image',
    source: { type: 'base64', media_type: 'image/png', data: 'AAAA' },
  };

  await $.session.append(
    resultRow([
      {
        type: 'tool_result',
        tool_use_id: 'toolu_1',
        content: [{ type: 'text', text: `a ${SECRET}` }, image, { type: 'text', text: 'clean' }],
      },
    ]),
  );

  expect(appended()[0]?.message.content).toEqual([
    {
      type: 'tool_result',
      tool_use_id: 'toolu_1',
      content: [{ type: 'text', text: `a ${POINTER}` }, image, { type: 'text', text: 'clean' }],
    },
  ]);
});

test('a subagent tool result is handled the same and keeps its agent', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  const asked = helper(on, pointerReply);

  await $.session.append(resultRow(asString(`key=${SECRET}`), { agentId: 'agent-7' }));
  await $.session.append(resultRow(asBlocks(`key=${SECRET}`), { agentId: 'agent-7' }));
  await $.session.append(resultRow(asString(`key=${SECRET}`)));

  expect(appended()[0]?.message.content).toEqual(asString(`key=${POINTER}`));
  expect(appended()[0]?.agentId).toBe('agent-7');
  expect(appended()[1]?.message.content).toEqual(asBlocks(`key=${POINTER}`));
  expect(appended()[2]?.message.content).toEqual(asString(`key=${POINTER}`));
  expect(asked).toHaveLength(3);
});

test('output PostToolUse already handled is untouched and spawns nothing', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  const asked = helper(on, pointerReply);
  const pointerized = asString(`key=${POINTER}`);
  const oneWay = asBlocks(`key=${ONE_WAY}`);

  await $.session.append(resultRow(pointerized));
  await $.session.append(resultRow(oneWay));

  expect(appended()[0]?.message.content).toEqual(pointerized);
  expect(appended()[1]?.message.content).toEqual(oneWay);
  expect(asked).toEqual([]);
});

test('only the value PostToolUse left raw is rewritten', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  const asked = helper(on, pointerReply);

  await $.session.append(resultRow(asString(`a=${POINTER}\nb=${SECRET}`)));

  expect(appended()[0]?.message.content).toEqual(asString(`a=${POINTER}\nb=${POINTER}`));
  expect(asked).toHaveLength(1);
});

test('clean output spawns nothing and is stored as made', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  const asked = helper(on, pointerReply);
  const made = resultRow(asString('total 4\ndrwxr-xr-x  src'));

  await $.session.append(made);

  expect(appended()[0]?.message).toEqual(made.message);
  expect(asked).toEqual([]);
});

const failures: [string, (on: Hooks) => void][] = [
  ['exits non-zero', (on) => void helper(on, { stdout: '', exitCode: 1 })],
  [
    'answers with the value still in it',
    (on) =>
      void helper(on, (request) => JSON.stringify({ v: 1, text: request.stdin.text, note: null })),
  ],
  ['is refused', (on) => void helper(on, { deny: 'ETIMEDOUT' })],
];

for (const [label, arrange] of failures) {
  test(`a helper that ${label} leaves the result as made`, async ($, on) => {
    redactSecrets(on);
    const appended = store(on);
    arrange(on);
    const made = asString(`key=${SECRET}`);

    await $.session.append(resultRow(made));
    expect(appended()[0]?.message.content).toEqual(made);
  });
}
