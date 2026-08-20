/**
 * The per-test store setup cost, which is a CI-reliability property rather than
 * a product one.
 *
 * A suite with per-test isolation opens a store in `beforeEach`, and
 * `openLocalDatabase` runs every migration in the ledger on a store that has
 * none. That work is identical on every test and its result is a file, so it
 * can be done once per worker and copied. This is the trend behind that: three
 * shapes of the same per-test sequence, at the same scale a real `beforeEach`
 * runs it.
 *
 *   migrate per test   mkdtemp → openLocalDatabase (22 migrations) → close → rm
 *   copy the file      mkdtemp → copyFileSync a prepared store → open → close → rm
 *   copy cached bytes  mkdtemp → writeFileSync bytes held in memory → open → …
 *
 * Measured on arm64 macOS 26.5.2 / Node 24.18.0, tinybench mean, two runs:
 *
 * | shape             |    run 1 |    run 2 |
 * | ----------------- | -------: | -------: |
 * | migrate per test  | 11.10 ms | 14.81 ms |
 * | copy the file     |  1.39 ms |  1.62 ms |
 * | copy cached bytes |  1.21 ms |  1.42 ms |
 *
 * Both runs put the template at roughly 9-10x the migrating shape. Two are
 * quoted rather than one because the migrating row alone moved from ±0.50% rme
 * to ±13.37% between them: the RATIO is what holds, which is exactly why this
 * reports a trend and asserts nothing.
 *
 * These are `vitest bench` figures, taken WITHOUT coverage instrumentation. The
 * test suites always run with it on, so what a real `beforeEach` pays is higher
 * than the first column — the paired suite measurement behind this change was
 * 2.14 s of `tests` time across 101 store-opening tests before, 0.529 s after.
 *
 * The third is what `test/helpers/store-template.ts` does, and the gap between
 * the last two is why: the store is ~470 KB, so re-reading a template file per
 * test is the larger half of a copy.
 *
 * This gates NOTHING, in line with every other bench in this repo — a
 * wall-clock check on a shared runner fails for reasons unrelated to the diff.
 * What it is for is the platform it was written for: Windows charges most for
 * file creation and fsync, CI has measured this work at roughly 30x its local
 * cost there, and the per-test migration is what put four packages' suites over
 * their hook ceilings. A regression here is a regression in how much of that
 * ceiling every store suite in the workspace consumes.
 *
 * The template is built OUTSIDE the timed region for the reason the corpus is
 * in `capture.bench.ts`: it is setup, it is paid once by construction, and
 * folding it in would measure the very thing this exists to stop paying.
 */
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, bench, describe } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { openLocalDatabase } from '../src/database.ts';

const DB_FILE = 'aka.db';

/** One prepared store, built once, standing in for the shared template. */
const templateHome = mkdtempSync(join(tmpdir(), 'aka-bench-template-'));
const templateDir = join(templateHome, 'data');
openLocalDatabase(templateDir).close();
const templateFile = join(templateDir, DB_FILE);
const templateBytes = readFileSync(templateFile);

// The template outlives every iteration, so it is the one tree nothing in a
// bench body can remove. Without this each `pnpm bench` leaves a store and the
// `.bak` a fresh migration writes beside it — about 1 MB a run — for the OS
// temp sweeper to find.
afterAll(() => {
  removeTree(templateHome);
});

/** The mkdtemp + data-dir pair every shape below starts from. */
function freshHome(prefix: string): { home: string; dataDir: string } {
  const home = mkdtempSync(join(tmpdir(), prefix));
  const dataDir = join(home, 'data');
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  return { home, dataDir };
}

describe('per-test store setup', () => {
  bench('migrate per test', () => {
    const { home, dataDir } = freshHome('aka-bench-migrate-');
    openLocalDatabase(dataDir).close();
    removeTree(home);
  });

  bench('copy a template file, then open', () => {
    const { home, dataDir } = freshHome('aka-bench-copy-');
    copyFileSync(templateFile, join(dataDir, DB_FILE));
    openLocalDatabase(dataDir).close();
    removeTree(home);
  });

  bench('write cached template bytes, then open', () => {
    const { home, dataDir } = freshHome('aka-bench-bytes-');
    // What `createStoreTemplate().seed()` does, minus the staging rename — the
    // rename is a correctness measure for a partially-written header, not part
    // of the cost being compared.
    const file = join(dataDir, DB_FILE);
    const staging = `${file}.template-partial`;
    writeAndRename(staging, file);
    openLocalDatabase(dataDir).close();
    removeTree(home);
  });
});

function writeAndRename(staging: string, file: string): void {
  writeFileSync(staging, templateBytes, { mode: 0o600 });
  renameSync(staging, file);
}
