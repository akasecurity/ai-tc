/**
 * The retry exists for a platform this suite does not run on, which is exactly
 * why it needs a test that does.
 *
 * `publishByRename` was added because the Windows leg — once its install step
 * was fixed and the attached suites could run there for the first time — failed
 * the policy cache's concurrent-publish cases with EPERM. POSIX `rename(2)`
 * replaces a destination no matter who holds it open, so nothing on macOS or
 * Linux can provoke the refusal this handles, and driven against a real rename
 * the retry branch would be dead code everywhere it is tested.
 *
 * So the failure is injected through the `move` seam: a fake that refuses a
 * bounded number of times then succeeds, and one that refuses forever. Between
 * them they pin that the retry retries, that it gives up rather than stalling a
 * hook, and that a code it was never meant to swallow is rethrown at once.
 */
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { publishByRename } from '../../src/attached/atomic-publish.ts';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'aka-atomic-publish-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const errno = (code: string): NodeJS.ErrnoException => Object.assign(new Error(code), { code });

describe('publishByRename', () => {
  it('lands the file through a real rename', async () => {
    // The positive control, and the one case that uses the default `move`.
    // Without it every assertion below could be satisfied by a function that
    // throws on the happy path too.
    const tmp = join(dir, 'cache.tmp');
    const file = join(dir, 'cache.json');
    await writeFile(tmp, '{"v":1}', 'utf8');

    await publishByRename(tmp, file);

    await expect(readFile(file, 'utf8')).resolves.toBe('{"v":1}');
  });

  it('survives a destination that is briefly locked, as Windows does', async () => {
    // Two refusals then success — the shape of a concurrent reader releasing a
    // handle. A single-attempt implementation fails this.
    let attempts = 0;
    const flaky = (): Promise<void> => {
      attempts += 1;
      if (attempts <= 2) return Promise.reject(errno('EPERM'));
      return Promise.resolve();
    };

    await expect(publishByRename('tmp', 'file', flaky)).resolves.toBeUndefined();
    expect(attempts).toBe(3);
  });

  it('gives up rather than stalling a hook when the lock never clears', async () => {
    // A destination held open indefinitely is not a race, and the caller is
    // better served by an error it can record than by a hook that waits.
    let attempts = 0;
    const always = (): Promise<void> => {
      attempts += 1;
      return Promise.reject(errno('EBUSY'));
    };

    await expect(publishByRename('tmp', 'file', always)).rejects.toThrow('EBUSY');
    expect(attempts).toBe(5);
  });

  it('rethrows a code the retry was never meant to swallow, immediately', async () => {
    // ENOENT means the temp file is gone — retrying cannot help, and hiding it
    // behind five attempts would delay a real error for no reason.
    let attempts = 0;
    const missing = (): Promise<void> => {
      attempts += 1;
      return Promise.reject(errno('ENOENT'));
    };

    await expect(publishByRename('tmp', 'file', missing)).rejects.toThrow('ENOENT');
    expect(attempts).toBe(1);
  });
});
