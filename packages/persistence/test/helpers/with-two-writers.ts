/**
 * Independent write handles on one store — the shape the product runs in.
 *
 * Plugin hooks, the CLI and the dashboard each open their own `LocalDatabase`
 * on the same `aka.db` with nothing between them; WAL and
 * `PRAGMA busy_timeout` are the only things that keep them apart. These
 * helpers put a test in that position: N connections, one file, no
 * coordination.
 *
 * `node:sqlite` is synchronous, so two handles in one thread interleave rather
 * than collide on their own. Handles alone prove the write paths coexist; pair
 * them with `lockStore` from fault-injection.ts to hold the write lock from
 * outside the thread and drive real contention.
 */
import type { LocalDatabase } from '../../src/database.ts';
import type { TempStore } from './temp-store.ts';
import { withTempStore } from './temp-store.ts';

/**
 * Run `fn` with two independent handles on one temp store. `store` is there
 * too, for a test that needs the paths or a third handle.
 *
 * An async `fn` is awaited before teardown, as in `withTempStore`.
 */
export function withTwoWriters<T>(
  fn: (a: LocalDatabase, b: LocalDatabase, store: TempStore) => T,
): T {
  return withWriters(
    2,
    (writers, store) => {
      const [a, b] = writers;
      if (!a || !b) {
        throw new Error('withTwoWriters(): expected two handles');
      }
      return fn(a, b, store);
    },
    'aka-two-writers-',
  );
}

/**
 * Run `fn` with `count` independent handles on one temp store — the N-writer
 * generalisation of `withTwoWriters`.
 *
 * The handles are opened one after another, so the store is already migrated
 * by the time `fn` runs. A test that needs two connections racing to create a
 * store from scratch — concurrent migrations, a first-mint fingerprint — wants
 * `withTempStore` and its `open()` instead.
 *
 * Opening up front also matters when the body reaches for `lockStore`: opening
 * a handle while the write lock is held fails, because `openLocalDatabase`
 * writes on the way in. Take the handles first, then lock.
 */
export function withWriters<T>(
  count: number,
  fn: (writers: LocalDatabase[], store: TempStore) => T,
  prefix = 'aka-writers-',
): T {
  if (!Number.isInteger(count) || count < 1) {
    throw new Error(`withWriters(): count must be a positive integer, got ${String(count)}`);
  }
  return withTempStore((store) => {
    const writers = Array.from({ length: count }, () => store.open());
    return fn(writers, store);
  }, prefix);
}
