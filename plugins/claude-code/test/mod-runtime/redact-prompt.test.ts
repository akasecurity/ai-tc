import { expect, test } from 'claude-code/testing';

import { SECRET } from './samples.generated.js';

// Runs the shipped hooks/mod.ts inside the real mod runtime. A hook registered
// by the test sits beneath the plugin and stands for the engine: what it
// receives is what the model would read, and whatever it returns is what the
// prompt becomes. See prepare.mjs for how the engine beside the module differs
// from the shipped one.

test('a secret reaches the model as a placeholder and the prompt is not blocked', async ($, on) => {
  const seen: string[] = [];
  on('prompt.submit', (_$, e) => {
    seen.push(e.text);
    return { text: e.text };
  });

  const result = await $.prompt.submit({ text: `deploy with ${SECRET} please` });

  expect(result.drop).toBeUndefined();
  expect(seen).toHaveLength(1);
  expect(seen[0]).toContain('[REDACTED:SECRET]');
  expect(seen[0]).not.toContain(SECRET);
  expect(result.text).toBe(seen[0]);
});

test('a prompt with no findings passes unchanged and without delay', async ($, on) => {
  const seen: string[] = [];
  on('prompt.submit', (_$, e) => {
    seen.push(e.text);
    return { text: e.text };
  });
  const text = 'rename this variable across the module';

  await $.prompt.submit({ text });
  const t0 = performance.now();
  await $.prompt.submit({ text });
  const elapsedMs = performance.now() - t0;

  expect(seen).toEqual([text, text]);
  expect(elapsedMs).toBeLessThan(250);
});

test('under the bundled default policy a secret is left for the command hook', async ($, on) => {
  const seen: string[] = [];
  on('prompt.submit', (_$, e) => {
    seen.push(e.text);
    return { text: e.text };
  });
  const text = `__DEFAULT_POLICY__ key ${SECRET}`;

  await $.prompt.submit({ text });

  expect(seen).toEqual([text]);
});

test('an engine that throws leaves the prompt unchanged', async ($, on) => {
  const seen: string[] = [];
  on('prompt.submit', (_$, e) => {
    seen.push(e.text);
    return { text: e.text };
  });
  const text = `__ENGINE_THROWS__ ${SECRET}`;

  const result = await $.prompt.submit({ text });

  expect(result.drop).toBeUndefined();
  expect(seen).toEqual([text]);
});
