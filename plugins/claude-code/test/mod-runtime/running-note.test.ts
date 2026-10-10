import { expect, test } from 'claude-code/testing';

import { HOME, model } from './harness.js';
import type { Hooks } from './harness.js';

// The note the mod leaves so `aka status` can say prompts are redacted in place.

const NOTES_DIR = [HOME, '.aka', 'data', 'mod-sessions'].join('/');

interface Writes {
  path: string;
  text: string;
}

function world(on: Hooks, sessionId: string, clock: { now: number }, refuse = false): Writes[] {
  const writes: Writes[] = [];
  on('env.get', (_$, e) => ({ value: e.name === 'HOME' ? HOME : undefined }));
  on('session.id', () => ({ value: sessionId }));
  on('clock.now', () => ({ value: clock.now }));
  on('session.start', (_$, e) => ({ cwd: e.cwd }));
  on('fs.write', (_$, e) => {
    if (refuse) return { deny: 'EACCES' };
    writes.push({ path: e.path, text: e.text });
    return { value: undefined };
  });
  return writes;
}

test('session start leaves a note naming the session', async ($, on) => {
  const writes = world(on, 'sess-a', { now: 1_000 });

  await $.session.start({ cwd: HOME, surface: null, isInteractive: true });

  expect(writes).toHaveLength(1);
  expect(writes[0]?.path).toBe(`${NOTES_DIR}/sess-a.json`);
  expect(JSON.parse(writes[0]?.text ?? 'null')).toEqual({ v: 1, sessionId: 'sess-a', at: 1_000 });
});

test('a prompt renews the note once a minute, not on every prompt', async ($, on) => {
  const clock = { now: 5_000 };
  const writes = world(on, 'sess-b', clock);
  model(on);

  await $.prompt.submit({ text: 'one' });
  clock.now = 5_000 + 30_000;
  await $.prompt.submit({ text: 'two' });
  clock.now = 5_000 + 61_000;
  await $.prompt.submit({ text: 'three' });

  expect(writes.map((w) => (JSON.parse(w.text) as { at: number }).at)).toEqual([5_000, 66_000]);
});

test('a refused write leaves the prompt untouched', async ($, on) => {
  world(on, 'sess-c', { now: 9_000 }, true);
  const seen = model(on);

  await $.session.start({ cwd: HOME, surface: null, isInteractive: true });
  const result = await $.prompt.submit({ text: 'hello' });

  expect(result.drop).toBeUndefined();
  expect(seen).toEqual(['hello']);
});
