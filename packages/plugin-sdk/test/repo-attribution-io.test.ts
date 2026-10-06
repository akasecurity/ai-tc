// The I/O promises resolveRepoAttribution makes on the capture path, pinned by
// counting: ONE ancestor walk and ONE config read for a directory it has not
// seen, NOTHING for one it has, and a bound on how many directories it keeps.
//
// It needs its own file because the seam is a `vi.mock` of `node:fs`, which is
// file-scoped. It has to be a module mock rather than a patch of the module
// object's properties: repo.ts binds `existsSync` and `readFileSync` through
// NAMED imports, which such a patch never reaches. A count taken through a seam
// that is not in the path reads zero, which is exactly what "no I/O" looks
// like, so the first case asserts that the interception fired.
import type * as FsModule from 'node:fs';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const io = vi.hoisted(() => ({
  probes: [] as string[],
  reads: [] as string[],
  // A path fragment whose `existsSync` throws, to drive the never-throws
  // contract. '' disarms it.
  failOn: '',
}));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof FsModule>();
  const existsSync = ((...args: Parameters<typeof actual.existsSync>) => {
    const path = String(args[0]);
    if (io.failOn !== '' && path.includes(io.failOn)) throw new Error('simulated fs fault');
    io.probes.push(path);
    return actual.existsSync(...args);
  }) as typeof actual.existsSync;
  const readFileSync = ((...args: Parameters<typeof actual.readFileSync>) => {
    io.reads.push(String(args[0]));
    return actual.readFileSync(...args);
  }) as typeof actual.readFileSync;
  return { ...actual, existsSync, readFileSync };
});

const { resolveRepo, resolveRepoAttribution } = await import('../src/repo.ts');

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-repo-io-'));
  io.failOn = '';
});

afterEach(() => {
  io.failOn = '';
  rmSync(root, { recursive: true, force: true });
});

function reset(): void {
  io.probes.length = 0;
  io.reads.length = 0;
}

// The ancestor walk is one `existsSync(<dir>/.git)` per directory climbed; the
// config read is the single `readFileSync(<gitdir>/config)`.
const walkProbes = (): number => io.probes.filter((p) => p.endsWith(`${sep}.git`)).length;
const configReads = (): number => io.reads.filter((p) => p.endsWith(`${sep}config`)).length;

function repoWithOrigin(name: string): string {
  const dir = join(root, name);
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(
    join(dir, '.git', 'config'),
    '[remote "origin"]\n\turl = https://github.com/org/payments-api.git\n',
  );
  return dir;
}

const PAYMENTS_API = { repo: 'payments-api', scopeKey: 'github.com/org/payments-api' };

describe('resolveRepoAttribution — I/O', () => {
  it('walks once and reads the config once: the I/O resolveRepo alone already does', () => {
    const nested = join(repoWithOrigin('repo'), 'apps', 'backend', 'src');
    mkdirSync(nested, { recursive: true });

    reset();
    expect(resolveRepo(nested)).toBe('payments-api');
    const slugWalk = walkProbes();
    // The interception fired. Without this, a seam that is not in the path
    // counts zero for both resolvers and every comparison below holds.
    expect(slugWalk).toBeGreaterThan(0);
    expect(configReads()).toBe(1);

    reset();
    expect(resolveRepoAttribution(nested)).toEqual(PAYMENTS_API);
    expect(walkProbes()).toBe(slugWalk);
    expect(configReads()).toBe(1);
  });

  it('answers a cwd it has already resolved from memory, touching nothing', () => {
    const dir = repoWithOrigin('repo');
    const first = resolveRepoAttribution(dir);

    reset();
    const again = resolveRepoAttribution(dir);
    expect(again).toBe(first);
    expect(io.probes).toEqual([]);
    expect(io.reads).toEqual([]);
  });

  it('remembers at most 64 directories, then starts over', () => {
    const repoRoot = repoWithOrigin('repo');
    // A cwd need not exist for the walk to resolve it (it climbs by name), and
    // the memo keys on the exact string, so each of these is a new entry.
    let fresh = 0;
    const freshCwd = (): string => {
      fresh += 1;
      return join(repoRoot, `cwd-${String(fresh)}`);
    };
    const anchor = join(repoRoot, 'anchor');
    const anchorIsRemembered = (): boolean => {
      reset();
      resolveRepoAttribution(anchor);
      return configReads() === 0;
    };

    // The memo is module state and the cases above left entries in it, so its
    // size is unknown here. Find the moment it starts over: feed it new cwds
    // until the anchor is forgotten. Re-resolving the anchor at that moment
    // leaves exactly two entries, the cwd that triggered the clear and the
    // anchor, which is the known state the rest of the case counts from. The
    // bound inside the loop is what fails if nothing is ever forgotten.
    resolveRepoAttribution(anchor);
    let fed = 0;
    while (anchorIsRemembered()) {
      resolveRepoAttribution(freshCwd());
      fed += 1;
      expect(fed).toBeLessThanOrEqual(64);
    }

    // Two entries. Sixty-two more fill it to the bound, and at 64 the anchor is
    // still answered from memory.
    for (let i = 0; i < 62; i += 1) resolveRepoAttribution(freshCwd());
    expect(anchorIsRemembered()).toBe(true);

    // One more finds it full and clears it: the anchor is read from disk again.
    resolveRepoAttribution(freshCwd());
    expect(anchorIsRemembered()).toBe(false);
  });

  it('answers a failing walk as empty, without throwing, and does not remember the failure', () => {
    const dir = repoWithOrigin('repo');
    io.failOn = dir;
    expect(resolveRepoAttribution(dir)).toEqual({});

    io.failOn = '';
    expect(resolveRepoAttribution(dir)).toEqual(PAYMENTS_API);
  });
});
