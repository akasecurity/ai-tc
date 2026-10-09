import { expect, test } from 'claude-code/testing';

import { contexts, fileSystem, helper, model, oneWay, snapshotText } from './harness.js';
import { SECRET } from './samples.generated.js';

// The aka helper is answered from beneath the mod, as the process would answer.
// What the model receives is the last hook in the chain (see harness.model).

// Spelled by joining so no pointer-shaped literal sits in the source. A pointer in
// the pinned grammar: [[aka:<category>:<key version>.<26 chars>.<16 chars>]]
const POINTER = ['[[aka:secret:', 'AB.', 'A'.repeat(26), '.', 'B'.repeat(16), ']]'].join('');
const NOTE = '[AKA 0123456789abcdef] prompt: AKA replaced 1 value before this ran.';

function redactSecrets(on: Parameters<Parameters<typeof test>[1]>[1], id: number): void {
  fileSystem(on, () => ({
    text: snapshotText({ categoryActions: { secret: 'redact' } }),
    mtimeMs: id,
  }));
}

function pointerReply(note: string | null = NOTE) {
  return (request: { stdin: { text: string } }) =>
    JSON.stringify({ v: 1, text: request.stdin.text.replace(SECRET, POINTER), note });
}

test('the model receives the vault pointer and a note explaining pointers', async ($, on) => {
  redactSecrets(on, 100);
  const seen = model(on);
  contexts.length = 0;
  const asked = helper(on, pointerReply());

  const result = await $.prompt.submit({ text: `deploy with ${SECRET} please` });

  expect(seen).toEqual([`deploy with ${POINTER} please`]);
  expect(result.drop).toBeUndefined();
  expect(contexts).toEqual([[NOTE]]);
  expect(asked).toHaveLength(1);
});

test('the helper is run with node on its script, a short timeout and the prompt on stdin', async ($, on) => {
  redactSecrets(on, 101);
  model(on);
  const asked = helper(on, pointerReply());

  await $.prompt.submit({ text: `deploy with ${SECRET} please` });

  expect(asked[0]?.argv[0]).toBe('node');
  expect(asked[0]?.argv[1]).toMatch(/[\\/]scripts[\\/]mod-tokenize\.js$/);
  expect(asked[0]?.timeoutMs).toBeLessThanOrEqual(3000);
  expect(asked[0]?.stdin).toMatchObject({
    v: 1,
    text: `deploy with ${SECRET} please`,
    sessionId: 'session-1',
  });
});

test('without consent the helper answers the one-way marker and no note is added', async ($, on) => {
  redactSecrets(on, 102);
  const seen = model(on);
  contexts.length = 0;
  helper(on, oneWay({ [SECRET]: '[REDACTED:SECRET]' }));

  await $.prompt.submit({ text: `deploy with ${SECRET} please` });

  expect(seen).toEqual(['deploy with [REDACTED:SECRET] please']);
  expect(contexts).toEqual([[]]);
});

test('a context the prompt already carried is kept beside the note', async ($, on) => {
  redactSecrets(on, 103);
  model(on);
  contexts.length = 0;
  helper(on, pointerReply());

  await $.prompt.submit({ text: `deploy with ${SECRET} please`, context: ['earlier'] } as never);

  expect(contexts).toEqual([['earlier', NOTE]]);
});

test('a clean prompt spawns nothing', async ($, on) => {
  redactSecrets(on, 104);
  const seen = model(on);
  const asked = helper(on, pointerReply());
  const text = 'rename this variable across the module';

  await $.prompt.submit({ text });

  expect(seen).toEqual([text]);
  expect(asked).toEqual([]);
});

test('a prompt that holds only a policy of log spawns nothing', async ($, on) => {
  fileSystem(on, () => ({ text: snapshotText(), mtimeMs: 105 }));
  const seen = model(on);
  const asked = helper(on, pointerReply());
  const text = `deploy with ${SECRET} please`;

  await $.prompt.submit({ text });

  expect(seen).toEqual([text]);
  expect(asked).toEqual([]);
});

test('a pointer already in the prompt is never sent for tokenizing', async ($, on) => {
  redactSecrets(on, 106);
  const seen = model(on);
  const asked = helper(on, pointerReply());
  const text = `deploy with ${POINTER} please`;

  await $.prompt.submit({ text });

  expect(seen).toEqual([text]);
  expect(asked).toEqual([]);
});

test('a pointer beside a new secret stays as it was and only the secret is tokenized', async ($, on) => {
  redactSecrets(on, 107);
  const seen = model(on);
  helper(on, pointerReply());

  await $.prompt.submit({ text: `use ${POINTER} and ${SECRET}` });

  expect(seen).toEqual([`use ${POINTER} and ${POINTER}`]);
});

const FAILURES: [string, Parameters<typeof helper>[1]][] = [
  ['is missing', { deny: 'ENOENT' }],
  ['times out', { deny: 'timed out' }],
  ['exits non-zero', { stdout: '', exitCode: 1 }],
  ['exits non-zero with output', { stdout: pointerReply()({ stdin: { text: 'x' } }), exitCode: 2 }],
  ['prints garbage', { stdout: 'not json' }],
  ['prints nothing', { stdout: '' }],
  ['prints the wrong version', { stdout: JSON.stringify({ v: 2, text: 'x', note: null }) }],
  ['prints no text', { stdout: JSON.stringify({ v: 1, note: null }) }],
  ['prints an empty text', { stdout: JSON.stringify({ v: 1, text: '', note: null }) }],
  ['prints a note that is not text', { stdout: JSON.stringify({ v: 1, text: 'x', note: 1 }) }],
  [
    'hands back a text that still holds the value',
    (() => {
      const echo = (request: { stdin: { text: string } }) =>
        JSON.stringify({ v: 1, text: request.stdin.text, note: NOTE });
      return echo as never;
    })(),
  ],
];

for (const [label, reply] of FAILURES) {
  test(`the helper ${label}: the prompt passes unchanged, not one-way redacted`, async ($, on) => {
    redactSecrets(on, 200);
    const seen = model(on);
    contexts.length = 0;
    helper(on, reply);
    const text = `deploy with ${SECRET} please`;

    const result = await $.prompt.submit({ text });

    expect(result.drop).toBeUndefined();
    expect(seen).toEqual([text]);
    expect(contexts).toEqual([[]]);
  });
}
