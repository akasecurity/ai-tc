import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';

/**
 * Temp directories for a suite that redirects `homedir()`, removed when the FILE
 * finishes rather than after each test.
 *
 * Anything such a suite renders opens the local store under whichever home was
 * current, and `app/lib/db.ts` holds that handle for the life of the process.
 * Removing the directory while it is still held is invisible on POSIX — the
 * files are unlinked and the open handle goes on serving them — and an outright
 * refusal on Windows, where `rmSync` raises EPERM and the suite fails in its own
 * teardown, naming a cleanup line and no test.
 *
 * Deferring to `afterAll` is what makes hook ORDER stop mattering: the store is
 * released and the directories removed inside one hook, in that order. Splitting
 * them across two hooks does not work — vitest's `sequence.hooks` defaults to
 * `stack`, so a suite's own `afterEach` runs BEFORE one a setup file registered,
 * and the removal would still go first.
 *
 * Every test still gets its own directory, so isolation is unchanged. All that
 * moves is when the bytes go away.
 */
/**
 * Let go of the store `app/lib/db.ts` holds, so the directory it lives in can be
 * removed.
 *
 * Dynamic, and only ever called from a teardown: a static import would load that
 * module — and @akasecurity/persistence beneath it — before a suite's own
 * `vi.mock('node:os')` is installed, so persistence would bind the real
 * homedir() and every redirect in the file would quietly stop working.
 */
export async function releaseLocalStore(): Promise<void> {
  const { closeStore } = await import('../../app/lib/db.ts');
  closeStore();
}

export function tempHomes(prefix: string): () => string {
  const made: string[] = [];

  afterAll(async () => {
    // Released first, then removed — one hook, explicit order.
    await releaseLocalStore();
    // Through `removeTrees`, not a bare `rmSync`. Releasing narrows the window in
    // which Windows refuses the removal but does not close it: the `-wal`/`-shm`
    // sidecars can outlive the connection for a moment, and a bare `rmSync` that
    // meets that fails this hook naming a cleanup line and no test — the failure
    // this helper exists to remove. `removeTrees` retries through that window,
    // tolerates it on win32 only, and attempts every directory before reporting.
    removeTrees(made.splice(0));
  });

  return () => {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    made.push(dir);
    return dir;
  };
}
