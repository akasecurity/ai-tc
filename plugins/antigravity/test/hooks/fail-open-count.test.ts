// The spawn `runHookFailOpen` counts a fail-open exit through, driven for real
// against stand-in children. The built child itself is covered by
// `test/e2e/fail-open-count-entry-bundle.e2e.test.ts`.
//
// Two properties are pinned. The spawn returns without waiting on its child:
// the hook exits right after it, and on this host a hook still running at its
// timeout is a deny, so a count that stalls must stall the child and never the
// hook. And the spawn never throws, since it runs between the payload and the
// exit.
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
});
