// The detached fail-open counting child, run in-process.
//
// The bundle e2e drives the built child as a real process, where coverage
// cannot see it; this imports the same source. The entry does its work at
// module load and ends by calling `process.exit`, so `exit` is stubbed and the
// module registry is reset before each import. `os.homedir()` is pointed at a
// throwaway home per case: a lookup with none set, or with `refuse`, throws
// rather than falling through to the real home.
import { mkdtempSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { readHookFailOpens } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';

const osHome = vi.hoisted(() => ({ dir: '', refuse: false }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return {
    ...actual,
    homedir: () => {
      if (osHome.refuse || osHome.dir === '') throw new Error('no home directory');
      return osHome.dir;
    },
  };
});

describe('the fail-open counting child', () => {
  let exit: MockInstance<typeof process.exit>;

  beforeEach(() => {
    osHome.dir = mkdtempSync(join(tmpdir(), 'aka-agy-fail-open-count-entry-'));
    exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as typeof process.exit);
    vi.resetModules();
  });

  afterEach(() => {
    exit.mockRestore();
    removeTree(osHome.dir);
    osHome.dir = '';
    osHome.refuse = false;
  });

  it('records one fail-open under the home it resolves, and exits 0', async () => {
    const before = Date.now();
    await import('../src/fail-open-count.ts');
    const after = Date.now();

    const tally = readHookFailOpens(join(osHome.dir, '.aka', 'data'));
    expect(tally?.failOpens).toBe(1);
    expect(tally?.lastAtMs).toBeGreaterThanOrEqual(before);
    expect(tally?.lastAtMs).toBeLessThanOrEqual(after);
    expect(exit).toHaveBeenCalledWith(0);
  });

  it('still exits 0, without throwing, when the platform cannot name a home', async () => {
    osHome.refuse = true;
    await expect(import('../src/fail-open-count.ts')).resolves.toBeDefined();
    expect(exit).toHaveBeenCalledWith(0);
  });
});
