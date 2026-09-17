// The spawn `runHookFailOpen` counts a fail-open exit through, driven for real
// against stand-in children. The built child itself is covered by
// `test/e2e/fail-open-count-entry-bundle.e2e.test.ts`.
//
// Two properties are pinned. The spawn returns without waiting on its child:
// the hook exits right after it, and on this host a hook still running at its
// timeout is a deny, so a count that stalls must stall the child and never the
// hook. And a spawn that fails costs nothing, whether the failure is thrown
// from the call or reported on a later tick, since it runs between the payload
// and the exit.
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { spawnFailOpenCount } from '../../src/hooks/shared.ts';

describe('spawnFailOpenCount', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-agy-fail-open-count-'));
  });

  afterEach(() => {
    removeTree(dir);
  });

  it('returns without waiting on the child it starts', async () => {
    // The stand-in writes its marker only after a pause, so a spawn that waited
    // on its child would return with the marker already on disk.
    const finished = join(dir, 'finished');
    const child = join(dir, 'slow-child.mjs');
    writeFileSync(
      child,
      `import { writeFileSync } from 'node:fs';\n` +
        `setTimeout(() => writeFileSync(${JSON.stringify(finished)}, ''), 1500);\n`,
    );

    spawnFailOpenCount(pathToFileURL(child));

    expect(existsSync(finished)).toBe(false);
    // The positive control: the child really started, and finishes on its own.
    await vi.waitFor(
      () => {
        expect(existsSync(finished)).toBe(true);
      },
      { timeout: 15_000, interval: 50 },
    );
  });

  it('never throws when the child cannot be started', () => {
    // A path carrying a NUL byte is refused synchronously, before any process
    // exists — the shape of the spawn failures Node throws rather than emits.
    const nul = String.fromCharCode(0);
    expect(() => {
      spawnFailOpenCount(pathToFileURL(join(dir, `fail-open-count${nul}.js`)));
    }).not.toThrow();
  });

  it('swallows a spawn failure reported on a later tick', async () => {
    // Some spawn failures (ENOENT, EACCES, EAGAIN, EMFILE) are not thrown:
    // `spawn` returns, and the child emits 'error' a tick later. Unheard, that
    // event is rethrown as an uncaught exception — a non-zero exit, and so a
    // deny, for a hook about to exit 0. A missing SCRIPT cannot reach it, since
    // node itself starts and only the child fails, so the executable is what
    // goes missing here. Without the `error` listener this case fails on the
    // uncaught event, and so does the run.
    const seen: unknown[] = [];
    const onUncaught = (error: unknown): void => {
      seen.push(error);
    };
    process.on('uncaughtException', onUncaught);
    try {
      const realExecPath = process.execPath;
      process.execPath = join(dir, 'missing-node-binary');
      try {
        spawnFailOpenCount(pathToFileURL(join(dir, 'never-started.mjs')));
      } finally {
        process.execPath = realExecPath;
      }
      // The failure arrives after the call has returned, so give it that turn.
      await new Promise((resolve) => setImmediate(resolve));
      expect(seen).toEqual([]);
    } finally {
      process.off('uncaughtException', onUncaught);
    }
  });
});
