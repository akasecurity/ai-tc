import type { DatabaseSync } from 'node:sqlite';

import { withTransaction } from '../internal/transactions.ts';
import { seedSampleAuditEvents } from './sample-audit-events.ts';
import { seedSampleInventory } from './sample-inventory.ts';
import { seedSampleShares } from './sample-shares.ts';

/**
 * TEST AND BENCHMARK FIXTURES ONLY. The product seeds no sample/demo data
 * (removed by product decision — the web-ui purges the retired dataset from
 * historical stores via sample-purge.ts). These rich fully-shaped datasets
 * survive purely as fixtures for the repository read-surface tests; nothing
 * outside `test/` may import this directory, so shipped bundles never contain
 * it. The importers today are three `*.test.ts` suites plus
 * `test/helpers/corpus.ts`, which is where the benchmarks reach the generator
 * from — no `*.bench.ts` imports this directory directly, and none should:
 * seeding a corpus needs the raw connection, and reading that seam outside
 * `test/` fails `packages/eslint-config/test/test-only-seam.test.js`.
 *
 * Two kinds live here and they answer different questions. `seedSampleFixtures`
 * and its parts are FIXED datasets — hand-authored rows shaped to exercise a
 * read surface. `generate.ts` is a deterministic GENERATOR, for the benchmark
 * harness: a store of a stated size, from a seed, because the sizes that matter
 * there cannot live in git.
 *
 * Unlike the retired product seeder there is no marker table and no emptiness
 * gating — tests own their stores and seed exactly once.
 */
export function seedSampleFixtures(db: DatabaseSync): void {
  // One transaction, not one per row. In autocommit each insert commits on its
  // own, and on a file-backed store every commit is a separate flush — the cost
  // the Windows CI runner charges orders of magnitude more for than a local
  // disk does, which is enough to put a seeding test near the per-test timeout.
  // withTransaction owns the BEGIN/COMMIT and the guarded ROLLBACK, and drops
  // to a SAVEPOINT when the caller already holds a transaction, so a failed
  // seed rethrows the real error rather than a ROLLBACK-on-an-aborted-tx one.
  withTransaction(db, () => {
    seedSampleShares(db);
    seedSampleInventory(db);
    seedSampleAuditEvents(db);
  });
}

export type {
  CaptureCorpusOptions,
  CaptureCorpusTarget,
  GeneratedCaptureCorpus,
} from './generate.ts';
export {
  CORPUS_EPOCH_MS,
  CORPUS_EVENT_SPACING_MS,
  createSeededRandom,
  generateCaptureCorpus,
} from './generate.ts';
export { seedSampleAuditEvents, seedSampleInventory, seedSampleShares };
