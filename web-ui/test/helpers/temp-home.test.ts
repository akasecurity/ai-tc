import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const TEST_ROOT = fileURLToPath(new URL('..', import.meta.url));

/**
 * Every `afterEach` body in a file, as source text.
 *
 * Brace-matched from the hook's opening `{` rather than regexed to the first
 * `}`, so a nested block inside the hook does not end it early. Crude on
 * purpose: this guard reads source rather than running it, and a reader should
 * be able to see exactly how much it can and cannot see.
 */
/** Every `*.test.ts` under `dir`, recursively. Plain node:fs — a guard that
 * needed a dependency to read the tree would be one more thing to keep. */
function testFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...testFiles(full));
    else if (entry.name.endsWith('.test.ts') || entry.name.endsWith('.test.tsx')) out.push(full);
  }
  return out;
}

function afterEachBodies(source: string): string[] {
  const bodies: string[] = [];
  for (
    let at = source.indexOf('afterEach(');
    at !== -1;
    at = source.indexOf('afterEach(', at + 1)
  ) {
    const open = source.indexOf('{', at);
    if (open === -1) continue;
    let depth = 0;
    for (let i = open; i < source.length; i += 1) {
      if (source[i] === '{') depth += 1;
      else if (source[i] === '}') {
        depth -= 1;
        if (depth === 0) {
          bodies.push(source.slice(open, i + 1));
          break;
        }
      }
    }
  }
  return bodies;
}

describe('a suite that redirects the home', () => {
  // The bug this pins, in full: anything these suites render opens the local
  // store under whichever home was current, and app/lib/db.ts holds that handle
  // for the process. A per-test removal of that directory is silently fine on
  // POSIX — the files are unlinked and the open handle keeps serving them — and
  // refused outright on Windows, where rmSync raises EPERM and the suite fails
  // in its own teardown naming a cleanup line and no test.
  //
  // Only the FIRST suite in a worker to open a store can fail that way, so the
  // failure moves between files as import order changes. That is exactly why
  // this is a guard and not a fix in one suite.
  it('never removes a directory tree from an afterEach', () => {
    const files = testFiles(TEST_ROOT);

    const offenders: string[] = [];
    for (const file of files) {
      const source = readFileSync(file, 'utf-8');
      // Only suites that redirect the home can put a store inside a temp tree.
      if (!source.includes('homedir: () =>')) continue;
      for (const body of afterEachBodies(source)) {
        if (/rmSync\([^)]*recursive:\s*true/.test(body)) {
          offenders.push(file.slice(TEST_ROOT.length));
        }
      }
    }

    // The exit, named in the failure rather than left for the reader to find.
    expect(
      offenders,
      'Remove the tree when the FILE finishes instead, via tempHomes() in ' +
        'test/helpers/temp-home.ts — it releases the store first, in the same hook. ' +
        'See akasecurity/ai-tc#486.',
    ).toEqual([]);
  });

  it('has suites that actually redirect it, so the scan above is not vacuous', () => {
    // Without this the guard passes just as well on a tree where nothing matches
    // its precondition — which is how a guard stops guarding without going red.
    const files = testFiles(TEST_ROOT);
    const redirecting = files.filter((f) => readFileSync(f, 'utf-8').includes('homedir: () =>'));
    expect(redirecting.length).toBeGreaterThan(10);
  });
});
