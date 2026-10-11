import { expect, test } from 'claude-code/testing';

import { EMAIL, fileSystem, helper, model, oneWay, snapshotText } from './harness.js';
import type { FileAnswer } from './harness.js';
import { SECRET } from './samples.generated.js';

test('a user policy of redact reaches the model as a placeholder and the prompt is not blocked', async ($, on) => {
  fileSystem(on, () => ({
    text: snapshotText({ categoryActions: { secret: 'redact' } }),
    mtimeMs: 1,
  }));
  const seen = model(on);
  helper(on, oneWay({ [SECRET]: '[REDACTED:SECRET]' }));

  const result = await $.prompt.submit({ text: `deploy with ${SECRET} please` });

  expect(result.drop).toBeUndefined();
  expect(seen).toHaveLength(1);
  expect(seen[0]).toContain('[REDACTED:SECRET]');
  expect(seen[0]).not.toContain(SECRET);
  expect(result.text).toBe(seen[0]);
});

test('a rule-level action beats its category', async ($, on) => {
  fileSystem(on, () => ({
    text: snapshotText({
      categoryActions: { secret: 'redact' },
      ruleActions: { 'secrets/twilio-key': 'log' },
    }),
    mtimeMs: 2,
  }));
  const seen = model(on);
  const text = `deploy with ${SECRET} please`;

  await $.prompt.submit({ text });

  expect(seen).toEqual([text]);
});

test('a custom pack in the snapshot is applied under the policy of its rule', async ($, on) => {
  const rule = {
    specVersion: 1,
    id: 'acme/ticket',
    name: 'Acme ticket',
    category: 'custom',
    severity: 'high',
    matcher: { type: 'regex', pattern: 'ACME-[0-9]{6}', flags: 'g' },
    examples: ['ACME-123456'],
  };
  fileSystem(on, () => ({
    text: snapshotText({ rules: [rule], ruleActions: { 'acme/ticket': 'redact' } }),
    mtimeMs: 3,
  }));
  const seen = model(on);
  helper(on, oneWay({ 'ACME-123456': '[REDACTED:CUSTOM]' }));

  await $.prompt.submit({ text: `see ACME-123456 and ${SECRET}` });

  expect(seen[0]).not.toContain('ACME-123456');
  expect(seen[0]).toMatch(/\[REDACTED:[A-Z_]+\] and /);
  // The snapshot's ruleset replaces the bundled packs, so the bundled secret
  // rule is not in force here.
  expect(seen[0]).toContain(SECRET);
});

test('a rule with an active exception is left to the command hook', async ($, on) => {
  fileSystem(on, () => ({
    text: snapshotText({
      categoryActions: { secret: 'redact' },
      exceptionRuleIds: ['secrets/twilio-key'],
    }),
    mtimeMs: 4,
  }));
  const seen = model(on);
  const text = `deploy with ${SECRET} please`;

  await $.prompt.submit({ text });

  expect(seen).toEqual([text]);
});

test('a block anywhere in the prompt leaves the whole prompt for the command hook', async ($, on) => {
  fileSystem(on, () => ({
    text: snapshotText({
      categoryActions: { secret: 'redact' },
      ruleActions: { 'core-pii/email': 'block' },
    }),
    mtimeMs: 5,
  }));
  const seen = model(on);
  const text = `mail ${EMAIL} about ${SECRET}`;

  await $.prompt.submit({ text });

  expect(seen).toEqual([text]);
});

test('a missing snapshot leaves the bundled defaults and does not fail the prompt', async ($, on) => {
  fileSystem(on, () => undefined);
  const seen = model(on);
  const text = `key ${SECRET}`;

  const result = await $.prompt.submit({ text });

  expect(result.drop).toBeUndefined();
  expect(seen).toEqual([text]);
});

test('a corrupt snapshot leaves the bundled defaults and does not fail the prompt', async ($, on) => {
  fileSystem(on, () => ({ text: '{"version":1,"ruleActions":', mtimeMs: 6 }));
  const seen = model(on);
  const text = `key ${SECRET}`;

  const result = await $.prompt.submit({ text });

  expect(result.drop).toBeUndefined();
  expect(seen).toEqual([text]);
});

test('a snapshot of the wrong shape is not used', async ($, on) => {
  fileSystem(on, () => ({
    text: JSON.stringify({ version: 2, ruleActions: {}, categoryActions: { secret: 'redact' } }),
    mtimeMs: 7,
  }));
  const seen = model(on);
  const text = `key ${SECRET}`;

  await $.prompt.submit({ text });

  expect(seen).toEqual([text]);
});

test('a snapshot over 4 MiB is never read', async ($, on) => {
  const reads = fileSystem(on, () => ({
    text: snapshotText({ categoryActions: { secret: 'redact' } }),
    size: 4 * 1024 * 1024 + 1,
    mtimeMs: 8,
  }));
  const seen = model(on);
  const text = `key ${SECRET}`;

  const result = await $.prompt.submit({ text });

  expect(result.drop).toBeUndefined();
  expect(reads).toEqual([]);
  expect(seen).toEqual([text]);
});

test('an unchanged snapshot is read once and a changed one is read again', async ($, on) => {
  let answer: FileAnswer = {
    text: snapshotText({ categoryActions: { secret: 'redact' } }),
    mtimeMs: 9,
  };
  const reads = fileSystem(on, () => answer);
  const seen = model(on);
  helper(on, oneWay({ [SECRET]: '[REDACTED:SECRET]' }));
  const text = `key ${SECRET}`;

  await $.prompt.submit({ text });
  await $.prompt.submit({ text });
  expect(reads).toHaveLength(1);
  expect(seen[1]).toContain('[REDACTED:SECRET]');

  answer = { text: snapshotText({ categoryActions: { secret: 'log' } }), mtimeMs: 10 };
  await $.prompt.submit({ text });
  expect(reads).toHaveLength(2);
  expect(seen[2]).toBe(text);
});

test('a prompt with no findings passes unchanged and without delay', async ($, on) => {
  fileSystem(on, () => ({
    text: snapshotText({ categoryActions: { secret: 'redact' } }),
    mtimeMs: 11,
  }));
  const seen = model(on);
  const text = 'rename this variable across the module';

  await $.prompt.submit({ text });
  const t0 = performance.now();
  await $.prompt.submit({ text });
  const elapsedMs = performance.now() - t0;

  expect(seen).toEqual([text, text]);
  expect(elapsedMs).toBeLessThan(250);
});

test('an engine that throws leaves the prompt unchanged', async ($, on) => {
  fileSystem(on, () => ({
    text: snapshotText({ categoryActions: { secret: 'redact' } }),
    mtimeMs: 12,
  }));
  const seen = model(on);
  const text = `__ENGINE_THROWS__ ${SECRET}`;

  const result = await $.prompt.submit({ text });

  expect(result.drop).toBeUndefined();
  expect(seen).toEqual([text]);
});
