import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { afterEach, describe, expect, it } from 'vitest';

import { closeStore, db } from '../../app/lib/db.ts';

/** The module's cache, reached the way the module itself reaches it. */
const cache = globalThis as unknown as { __akaDb?: unknown };

const dirs: string[] = [];
function tempStoreDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aka-close-store-'));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  closeStore();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

// `closeStore()` is the whole mechanism behind test/helpers/temp-home.ts: the
// directories are removed only once it has run. A close that quietly failed to
// release the handle would leave the teardown green here and the Windows leg red,
// which is precisely the failure this change exists to remove — so the assertions
// below are about the HANDLE, not about the function returning.
describe('closeStore', () => {
  it('actually closes the handle, rather than merely forgetting it', async () => {
    // The load-bearing one. A body of `store.__akaDb = undefined` with no close
    // passes every other case in this file and ships the original bug.
    const held = openLocalDatabase(join(tempStoreDir(), 'data'));
    cache.__akaDb = held;

    // `transaction()` opens a real SQLite transaction on the handle, so it is
    // the one surface here that cannot answer on a closed one. The read paths
    // are fail-open by design and would return the same either way, which is
    // exactly why they cannot tell a release from a dropped reference.
    await expect(held.transaction(() => 1)).resolves.toBe(1);

    closeStore();

    expect(cache.__akaDb).toBeUndefined();
    await expect(held.transaction(() => 1)).rejects.toThrow();
  });

  it('leaves nothing cached, so the next db() has to open its own', () => {
    const held = openLocalDatabase(join(tempStoreDir(), 'data'));
    cache.__akaDb = held;

    closeStore();
    // Not asserted through db() itself: that would resolve a path this test does
    // not control and open a store under the real home. An empty cache is the
    // precondition db() reads, and it is the part this function owns.
    expect(cache.__akaDb).toBeUndefined();
    expect(db).toBeTypeOf('function');
  });

  it('calls close on the handle it lets go of', () => {
    // The narrowest statement of the same property, with no store involved: a
    // body that only cleared the cache would satisfy every assertion in this
    // file except this one and the transaction above.
    let closed = false;
    cache.__akaDb = {
      close() {
        closed = true;
      },
    };

    closeStore();

    expect(closed).toBe(true);
    expect(cache.__akaDb).toBeUndefined();
  });

  it('is a no-op when nothing is held', () => {
    // The teardown runs after EVERY test, including the many that never open a
    // store. Throwing there would turn one suite's red into the whole file's.
    expect(cache.__akaDb).toBeUndefined();
    expect(() => {
      closeStore();
      closeStore();
    }).not.toThrow();
  });

  it('clears the cache even when the close itself throws', () => {
    // Cleanup must not strand a dead handle as the live one: whatever went wrong
    // with this close, the next db() has to be free to open a working store.
    cache.__akaDb = {
      close() {
        throw new Error('already closed');
      },
    };

    expect(() => {
      closeStore();
    }).not.toThrow();
    expect(cache.__akaDb).toBeUndefined();
  });
});
