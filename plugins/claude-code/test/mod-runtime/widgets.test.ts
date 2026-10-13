import { expect, test } from 'claude-code/testing';

import { FINDINGS_PATH, fileSystem, helper, model, snapshotText } from './harness.js';
import type { Hooks } from './harness.js';
import { SECRET } from './samples.generated.js';

// The mod's findings store: what it holds from helper answers and from the
// session's findings file, observed through the version counter in $.state.

const record = (id: string, extra: Record<string, unknown> = {}) => ({
  v: 1,
  id,
  at: '2026-10-13T10:00:00.000Z',
  ruleId: 'secrets/test-key',
  shortName: 'Test key',
  category: 'secret',
  severity: 'high',
  action: 'redacted',
  where: 'prompt',
  ...extra,
});
const ID_A = 'a'.repeat(16);
const ID_B = 'b'.repeat(16);

const SECRET_REDACT = {
  text: snapshotText({ categoryActions: { secret: 'redact' } }),
  mtimeMs: 1,
};

// Every value written to the findings counter, as a plugin hooking state.set sees it.
function counter(on: Hooks): unknown[] {
  const values: unknown[] = [];
  on('state.set', (_$, e, next) => {
    const write = e as { key?: unknown; value?: unknown };
    if (write.key === 'findings') values.push(write.value);
    return next(e);
  });
  return values;
}

function answering(on: Hooks, findings: unknown) {
  return helper(on, (request) =>
    JSON.stringify({
      v: 1,
      text: request.stdin.text.replaceAll(SECRET, '[REDACTED:SECRET]'),
      note: null,
      findings,
    }),
  );
}

const prompt = `deploy with ${SECRET} please`;

test('a finding in the tokenize helper answer is held', async ($, on) => {
  const bumps = counter(on);
  fileSystem(on, () => SECRET_REDACT);
  model(on);
  answering(on, [record(ID_A)]);

  await $.prompt.submit({ text: prompt });

  expect(bumps).toEqual([1]);
});

test('an invalid finding is dropped and does not fail the answer', async ($, on) => {
  const bumps = counter(on);
  fileSystem(on, () => SECRET_REDACT);
  const seen = model(on);
  answering(on, [record(ID_A, { action: 'vaulted' }), 'junk', record(ID_B)]);

  await $.prompt.submit({ text: prompt });

  expect(seen[0]).toContain('[REDACTED:SECRET]');
  expect(bumps).toEqual([1]);
});

test('a findings value that is not a list is read as none', async ($, on) => {
  const bumps = counter(on);
  fileSystem(on, () => SECRET_REDACT);
  const seen = model(on);
  answering(on, { not: 'a list' });

  await $.prompt.submit({ text: prompt });

  expect(seen[0]).toContain('[REDACTED:SECRET]');
  expect(bumps).toEqual([]);
});

test('the same finding from the helper and the file is held once', async ($, on) => {
  const bumps = counter(on);
  const line = JSON.stringify(record(ID_A));
  fileSystem(
    on,
    () => SECRET_REDACT,
    () => ({ text: `${line}\n`, mtimeMs: 5 }),
  );
  model(on);
  answering(on, [record(ID_A)]);

  await $.prompt.submit({ text: prompt });

  expect(bumps).toEqual([1]);
});

test('a truncated last line in the file leaves the complete lines taken', async ($, on) => {
  const bumps = counter(on);
  const text = `${JSON.stringify(record(ID_A))}\n${JSON.stringify(record(ID_B))}\n{"v":1,"id":"cccc`;
  fileSystem(
    on,
    () => SECRET_REDACT,
    () => ({ text, mtimeMs: 6 }),
  );
  model(on);
  answering(on, []);

  await $.prompt.submit({ text: 'nothing sensitive here' });

  expect(bumps).toEqual([1]);
});

test('a file over 4 MiB per stat is not read', async ($, on) => {
  const bumps = counter(on);
  const reads = fileSystem(
    on,
    () => SECRET_REDACT,
    () => ({ text: JSON.stringify(record(ID_A)), size: 4 * 1024 * 1024 + 1, mtimeMs: 7 }),
  );
  model(on);
  answering(on, []);

  await $.prompt.submit({ text: 'hello' });

  expect(reads).not.toContain(FINDINGS_PATH);
  expect(bumps).toEqual([]);
});

test('an unchanged file is read once', async ($, on) => {
  const bumps = counter(on);
  const reads = fileSystem(
    on,
    () => SECRET_REDACT,
    () => ({ text: JSON.stringify(record(ID_A)), mtimeMs: 8 }),
  );
  model(on);
  answering(on, []);

  await $.prompt.submit({ text: 'one' });
  await $.prompt.submit({ text: 'two' });

  expect(reads.filter((path) => path === FINDINGS_PATH)).toHaveLength(1);
  expect(bumps).toEqual([1]);
});

test('only numbers are ever written under aka', async ($, on) => {
  const written: { key?: unknown; value?: unknown }[] = [];
  on('state.set', (_$, e, next) => {
    written.push(e as never);
    return next(e);
  });
  fileSystem(
    on,
    () => SECRET_REDACT,
    () => ({ text: JSON.stringify(record(ID_B)), mtimeMs: 9 }),
  );
  model(on);
  answering(on, [record(ID_A)]);

  await $.prompt.submit({ text: prompt });

  expect(written.length).toBeGreaterThan(0);
  const all = JSON.stringify(written);
  expect(all).not.toContain('secrets/test-key');
  expect(all).not.toContain('Test key');
  for (const write of written) {
    const value = (write as { value?: unknown }).value;
    expect(typeof value).toBe('number');
  }
});
