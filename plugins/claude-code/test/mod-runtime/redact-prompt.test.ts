import { expect, mock, test } from 'claude-code/testing';

import { SECRET } from './samples.generated.js';

// Runs the shipped hooks/mod.ts inside the real mod runtime. Beneath the plugin,
// hooks of the test answer the home directory and the policy snapshot the way the
// file system would, and a last hook stands for the model: what it receives is
// what the model would read. See prepare.mjs for how the engine beside the module
// differs from the shipped one.

type Hooks = Parameters<Parameters<typeof test>[1]>[1];

// Spelled by joining so no path or address literal sits in the source.
const HOME = ['', 'home', 'test'].join('/');
const SNAPSHOT_PATH = [HOME, '.aka', 'data', 'mod-policy.json'].join('/');
const EMAIL = ['a', 'example.com'].join('@');

const ALL_CATEGORIES = [
  'pii',
  'financial',
  'secret',
  'phi',
  'code_context',
  'code_flaw',
  'custom',
  'config',
];

interface SnapshotParts {
  rules?: unknown[];
  ruleActions?: Record<string, string>;
  categoryActions?: Record<string, string>;
  exceptionRuleIds?: string[];
}

// A snapshot as `aka` writes it: every category resolved, `log` unless said.
function snapshotText(parts: SnapshotParts = {}): string {
  return JSON.stringify({
    version: 1,
    generatedAt: '2026-10-09T00:00:00.000Z',
    ...(parts.rules !== undefined ? { rules: parts.rules } : {}),
    ruleActions: parts.ruleActions ?? {},
    categoryActions: {
      ...Object.fromEntries(ALL_CATEGORIES.map((c) => [c, 'log'])),
      ...parts.categoryActions,
    },
    exceptionRuleIds: parts.exceptionRuleIds ?? [],
  });
}

interface FileAnswer {
  text: string;
  size?: number;
  mtimeMs: number;
}

// What the file system beneath the plugin answers for the snapshot path: a value
// where the file is, a refusal (as a missing file is) where it is not.
function fileSystem(on: Hooks, file: () => FileAnswer | undefined): string[] {
  const reads: string[] = [];
  mock.env(on, { HOME });
  on('fs.stat', (_$, e) => {
    const answer = file();
    if (answer === undefined || e.path !== SNAPSHOT_PATH) return { deny: 'ENOENT' };
    return {
      value: {
        kind: 'file' as const,
        size: answer.size ?? answer.text.length,
        mtimeMs: answer.mtimeMs,
        isLink: false,
      },
    };
  });
  on('fs.read', (_$, e) => {
    reads.push(e.path);
    const answer = file();
    return answer === undefined ? { deny: 'ENOENT' } : { value: answer.text };
  });
  return reads;
}

// The model's end of the chain: records the prompt as it arrives.
function model(on: Hooks): string[] {
  const seen: string[] = [];
  on('prompt.submit', (_$, e) => {
    seen.push(e.text);
    return { text: e.text };
  });
  return seen;
}

test('a user policy of redact reaches the model as a placeholder and the prompt is not blocked', async ($, on) => {
  fileSystem(on, () => ({
    text: snapshotText({ categoryActions: { secret: 'redact' } }),
    mtimeMs: 1,
  }));
  const seen = model(on);

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
