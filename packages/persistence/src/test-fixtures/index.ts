import type { DatabaseSync } from 'node:sqlite';

import { withTransaction } from '../internal/transactions.ts';
import { seedSampleAuditEvents } from './sample-audit-events.ts';
import { seedSampleInventory } from './sample-inventory.ts';
import { seedSampleShares } from './sample-shares.ts';

/**
 * TEST AND BENCHMARK FIXTURES ONLY. The product seeds no sample/demo data
 * (removed by product decision — the web-ui purges the retired dataset from
 * historical stores via sample-purge.ts). These rich fully-shaped datasets
 * survive purely as fixtures for the repository read-surface tests and the
 * benchmark harness.
 *
 * Only a package's own test/ and bench/ files may import this directory, and
 * src/index.ts never re-exports it — which is what keeps it out of shipped
 * bundles, since `noExternal` inlines this package into the CLI and all three
 * plugins. The rule is about DIRECTORIES, not filename suffixes: the first
 * importer outside a spec is test/helpers/corpus.ts, which is neither a
 * *.test.ts nor a *.bench.ts. It is derived from the tracked tree by
 * packages/eslint-config/test/test-fixtures-imports.test.js rather than being
 * left to this comment — the check lives there because only that task's turbo
 * inputs hash the whole workspace.
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
export { createSeededRandom, generateCaptureCorpus } from './generate.ts';
export { seedSampleAuditEvents, seedSampleInventory, seedSampleShares };
