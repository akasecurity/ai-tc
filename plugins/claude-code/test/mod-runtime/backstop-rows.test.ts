import { expect, mock, test } from 'claude-code/testing';
import type { SessionAppendInput } from 'claude-code';

import { fileSystem, helper, snapshotText } from './harness.js';
import type { Hooks } from './harness.js';
import { SECRET } from './samples.generated.js';

// The row backstop at the seam: session.append is raised by the engine for each
// row the conversation keeps; the helper and the store are answered from beneath.

// Spelled by joining so no pointer-shaped literal sits in the source.
const POINTER = ['[[aka:secret:', 'AB.', 'A'.repeat(26), '.', 'B'.repeat(16), ']]'].join('');

let nextId = 200;
function redactSecrets(on: Hooks): void {
  nextId += 1;
  fileSystem(on, () => ({
    text: snapshotText({ categoryActions: { secret: 'redact' } }),
    mtimeMs: nextId,
  }));
}

// The conversation's end of the chain: the rows as stored.
function store(on: Hooks): () => readonly SessionAppendInput[] {
  return mock.session(on).appended;
}

function pointerReply(request: { stdin: { text: string } }): string {
  return JSON.stringify({ v: 1, text: request.stdin.text.replaceAll(SECRET, POINTER), note: null });
}

function row(
  door: SessionAppendInput['door'],
  text: string,
  extra: Partial<SessionAppendInput> = {},
): SessionAppendInput {
  return {
    message: { type: 'user', role: 'user', isMeta: true, content: [{ type: 'text', text }] },
    door,
    origin: { kind: 'engine' },
    uuid: `row-${door}`,
    ...extra,
  };
}

const textOf = (e: SessionAppendInput | undefined): string[] =>
  (e?.message.content ?? []).flatMap((b) => (b.type === 'text' ? [b.text] : []));

for (const [door, label] of [
  ['attachment', 'an @-mentioned file attachment'],
  ['hook-context', 'a hook or memory context row'],
  ['compaction', 'a compaction summary'],
  ['response', 'a response block'],
] as const) {
  test(`a secret in ${label} reaches the conversation only as a pointer`, async ($, on) => {
    redactSecrets(on);
    const appended = store(on);
    const asked = helper(on, pointerReply);

    await $.session.append(row(door, `file contents: key=${SECRET}\nmore`));

    expect(textOf(appended()[0])).toEqual([`file contents: key=${POINTER}\nmore`]);
    expect(asked).toHaveLength(1);
    expect(asked[0]?.stdin.row).toEqual({ door });
  });
}

test('a subagent row is scanned the same way and keeps its agent', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  helper(on, pointerReply);

  await $.session.append(row('attachment', `key=${SECRET}`, { agentId: 'agent-7' }));

  expect(textOf(appended()[0])).toEqual([`key=${POINTER}`]);
  expect(appended()[0]?.agentId).toBe('agent-7');
});

test('a subagent prompt row is scanned though a main prompt row is not', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  const asked = helper(on, pointerReply);

  await $.session.append(row('prompt', `key=${SECRET}`, { agentId: 'agent-7' }));
  expect(textOf(appended()[0])).toEqual([`key=${POINTER}`]);

  await $.session.append(row('prompt', `key=${SECRET}`));
  expect(textOf(appended()[1])).toEqual([`key=${SECRET}`]);
  expect(asked).toHaveLength(1);
});

test('an existing pointer is never re-tokenized', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  const asked = helper(on, pointerReply);
  const text = `already ${POINTER} here`;

  await $.session.append(row('attachment', text));

  expect(textOf(appended()[0])).toEqual([text]);
  expect(asked).toEqual([]);
});

test('a clean row spawns nothing and is stored as made', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  const asked = helper(on, pointerReply);
  const made = row('attachment', 'rename this variable across the module');

  await $.session.append(made);

  expect(appended()[0]?.message).toEqual(made.message);
  expect(asked).toEqual([]);
});

test('only text blocks are read; others pass through in place', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  helper(on, pointerReply);
  const image = {
    type: 'image',
    source: { type: 'base64', media_type: 'image/png', data: 'AAAA' },
  } as const;

  await $.session.append({
    ...row('attachment', ''),
    message: {
      type: 'user',
      role: 'user',
      content: [{ type: 'text', text: `a ${SECRET}` }, image, { type: 'text', text: 'clean' }],
    },
  });

  expect(appended()[0]?.message.content).toEqual([
    { type: 'text', text: `a ${POINTER}` },
    image,
    { type: 'text', text: 'clean' },
  ]);
});

test('a helper that fails leaves the row as made', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  helper(on, { stdout: '', exitCode: 1 });
  const text = `key=${SECRET}`;

  await $.session.append(row('attachment', text));
  expect(textOf(appended()[0])).toEqual([text]);
});

test('a helper that is refused or answers something else leaves the row as made', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  const text = `key=${SECRET}`;

  helper(on, { deny: 'ETIMEDOUT' });
  await $.session.append(row('attachment', text));
  expect(textOf(appended()[0])).toEqual([text]);
});

test('a rewrite that still holds the value is not stored', async ($, on) => {
  redactSecrets(on);
  const appended = store(on);
  helper(on, (request) => JSON.stringify({ v: 1, text: request.stdin.text, note: null }));
  const text = `key=${SECRET}`;

  await $.session.append(row('attachment', text));
  expect(textOf(appended()[0])).toEqual([text]);
});

test('a missing snapshot leaves the bundled defaults, which redact nothing', async ($, on) => {
  fileSystem(on, () => undefined);
  const appended = store(on);
  const asked = helper(on, pointerReply);
  const text = `key=${SECRET}`;

  await $.session.append(row('attachment', text));
  expect(textOf(appended()[0])).toEqual([text]);
  expect(asked).toEqual([]);
});

test('the scan of a large clean row is cheap', async ($, on) => {
  redactSecrets(on);
  store(on);
  const asked = helper(on, pointerReply);
  const big =
    'const total = items.map((i) => i.price * i.qty).reduce((a, b) => a + b, 0);\n'.repeat(1400);

  await $.session.append(row('attachment', big));
  const t0 = performance.now();
  await $.session.append(row('attachment', big));
  const ms = performance.now() - t0;
  console.log(`large-row scan ${String(big.length)} chars: ${ms.toFixed(1)} ms`);

  expect(asked).toEqual([]);
  expect(ms).toBeLessThan(500);
});
