/**
 * A temp store carrying a generated capture corpus — the store harness entry
 * point every scale benchmark and scale test starts from.
 *
 * `generateCaptureCorpus` needs two things a `LocalDatabase` does not hand out
 * together: its `recordCapture`, and the CONNECTION that call writes through, so
 * the whole corpus can sit inside one transaction. The second is
 * `UNSAFE_TEST_ONLY_RAW_HANDLE`, a test-only seam no shipped source may name
 * (`packages/eslint-config/test/test-only-seam.test.js`), which is why the read
 * lives here rather than in `src/test-fixtures/` — a helper under `test/` is on
 * the side of that audit that is allowed to reach it, and the store harness is
 * already where this package puts store setup.
 *
 * The wrapper `TempStore.open()` hands back is a spread copy, and the seam is an
 * enumerable own symbol, so it survives the spread — `test/raw-handle-seam.test.ts`
 * pins that rather than leaving it to this comment.
 *
 * `corpusConnection` is here for the same reason and is the only way a BENCHMARK
 * should reach the connection. `bench/` is not a `test/` path, so that audit
 * reads a `*.bench.ts` naming the seam as a product caller and fails the
 * workspace — correctly, since its classifier is deliberately wrong in the
 * excusing direction. Routing the read through this helper keeps the seam on the
 * side of the audit that already permits it.
 */
import type { DatabaseSync } from 'node:sqlite';

import type { LocalDatabase } from '../../src/database.ts';
import { UNSAFE_TEST_ONLY_RAW_HANDLE } from '../../src/database.ts';
import type {
  CaptureCorpusOptions,
  GeneratedCaptureCorpus,
} from '../../src/test-fixtures/index.ts';
import { generateCaptureCorpus } from '../../src/test-fixtures/index.ts';

export { CORPUS_EPOCH_MS, CORPUS_EVENT_SPACING_MS } from '../../src/test-fixtures/index.ts';
export type { CaptureCorpusOptions, GeneratedCaptureCorpus };

/**
 * The `DatabaseSync` a `LocalDatabase` writes through.
 *
 * A repository constructed over this one sees exactly the rows the facade
 * wrote — a second handle on the same file would carry none of an enclosing
 * transaction.
 */
export function corpusConnection(db: LocalDatabase): DatabaseSync {
  return db[UNSAFE_TEST_ONLY_RAW_HANDLE];
}

/**
 * Seed `db` with a generated corpus, writing through its own connection.
 *
 * Throws if the rows are not on disk afterwards — see the fail-open note on
 * `generateCaptureCorpus`. A benchmark has no assertions of its own, so this is
 * the only thing standing between it and timing an empty store.
 */
export function seedCaptureCorpus(
  db: LocalDatabase,
  options: CaptureCorpusOptions,
): GeneratedCaptureCorpus {
  return generateCaptureCorpus(
    {
      // Wrapped rather than passed as `db.recordCapture`. `LocalDatabase`
      // declares it as a method, so handing it over unbound trips
      // `@typescript-eslint/unbound-method` — correctly in general, even though
      // this particular one is a closure over the connection and reads no
      // `this`. The wrapper says that rather than silencing the rule.
      recordCapture: (event, findings) => {
        db.recordCapture(event, findings);
      },
      connection: db[UNSAFE_TEST_ONLY_RAW_HANDLE],
    },
    options,
  );
}
