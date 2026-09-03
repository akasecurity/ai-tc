/**
 * The activity page's read surface against the local store at two sizes an
 * order of magnitude apart — the SQLite twin of the hosted control plane's
 * activity bench, on the same corpus shape, so the two stores can be compared
 * read for read.
 *
 * One case per read the OSS dashboard makes on a page load (stats, the session
 * list, the token chip, the harness facet, a session's detail) plus the list's
 * filtered forms. The corpus is `seedActivityCorpus`, which mirrors a real
 * single-machine store observed 2026-09-03; see the helper for its shape.
 *
 *   pnpm --filter @akasecurity/persistence bench -- bench/activity-page.bench.ts
 *
 * NO ASSERTIONS: a measurement, not a gate. What must HOLD about these reads
 * is asserted as a query plan (`test/performance/activity-probe-plans.test.ts`,
 * `hot-read-query-plans.test.ts`) and as a ratio across two store sizes
 * (`test/performance/activity-page-scale.test.ts`).
 */
import { bench, describe } from 'vitest';

import { SqliteActivityRepository } from '../src/repositories/activity.ts';
import type { ActivityCorpus } from '../test/helpers/activity-corpus.ts';
import { seedActivityCorpus } from '../test/helpers/activity-corpus.ts';
import { corpusConnection } from '../test/helpers/corpus.ts';
import type { OwnedTempStore } from '../test/helpers/temp-store.ts';
import { createTempStore } from '../test/helpers/temp-store.ts';

/** Captures per corpus; the larger is the real store's size, the smaller a tenth of it. */
const SCALES = [20_000, 200_000] as const;

const DAY_MS = 86_400_000;

interface Surfaces {
  readonly store: OwnedTempStore;
  readonly activity: SqliteActivityRepository;
  readonly corpus: ActivityCorpus;
}

const fixtures = new Map<number, Surfaces>();

function fixtureFor(captures: number): Surfaces {
  const existing = fixtures.get(captures);
  if (existing) return existing;
  const store = createTempStore(`aka-bench-activity-${String(captures)}-`, { migrated: true });
  const raw = corpusConnection(store.open());
  const corpus = seedActivityCorpus(raw, { captures });
  // The clock is the corpus's own end, so "today" and the ranges hold rows.
  const surfaces: Surfaces = {
    store,
    activity: new SqliteActivityRepository(raw, () => corpus.endsAt),
    corpus,
  };
  fixtures.set(captures, surfaces);
  return surfaces;
}

const fromIso = (s: Surfaces, days: number): string =>
  new Date(s.corpus.endsAt - days * DAY_MS).toISOString();

const READS: readonly (readonly [string, (s: Surfaces) => Promise<unknown>])[] = [
  ['stats: today', (s) => s.activity.stats('UTC')],
  ['sessions: 7d', (s) => s.activity.listSessions({ from: fromIso(s, 7), excludeEmpty: true, limit: 100 })],
  ['sessions: 30d', (s) => s.activity.listSessions({ from: fromIso(s, 30), excludeEmpty: true, limit: 100 })],
  ['sessions: 7d show-empty', (s) => s.activity.listSessions({ from: fromIso(s, 7), excludeEmpty: false, limit: 100 })],
  ['sessions: 7d harness', (s) => s.activity.listSessions({ from: fromIso(s, 7), excludeEmpty: true, harness: ['codex'], limit: 100 })],
  ['sessions: 7d q', (s) => s.activity.listSessions({ from: fromIso(s, 7), excludeEmpty: true, q: 'repo-3', limit: 100 })],
  ['sessions: 30d q', (s) => s.activity.listSessions({ from: fromIso(s, 30), excludeEmpty: true, q: 'repo-3', limit: 100 })],
  ['harness facets: 30d', (s) => s.activity.harnessFacets(s.corpus.endsAt - 30 * DAY_MS)],
  ['token-usage: 7d', (s) => s.activity.tokenReports(s.corpus.endsAt - 7 * DAY_MS)],
  ['token-usage: 30d', (s) => s.activity.tokenReports(s.corpus.endsAt - 30 * DAY_MS)],
  ['session: median', (s) => s.activity.getSession(s.corpus.medianSessionId)],
  ['session: largest', (s) => s.activity.getSession(s.corpus.largestSessionId)],
];

const OPTIONS = { time: 2000, iterations: 3 };

for (const captures of SCALES) {
  describe(`/activity at ${captures.toLocaleString('en-US')} captures`, () => {
    for (const [name, run] of READS) {
      bench(
        name,
        async () => {
          await run(fixtureFor(captures));
        },
        {
          ...OPTIONS,
          setup: () => {
            fixtureFor(captures);
          },
        },
      );
    }
  });
}
