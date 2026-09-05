/**
 * The findings page's read surface at a stated store size.
 *
 * `/findings` is three views over one filtered set, and each view is a
 * different read rather than one read shaped three ways: the by-type list
 * (`listFindingTypes`, one row per rule, plus `listFindingInstances` scoped to
 * the selected rule for the detail panel beside it), the flat list
 * (`listFindingInstances`, one row per finding, keyset-paged) and the locations
 * fold (`listFindingLocations`, repo then file). Every filter change re-runs
 * the view's read from the top of its scope, because totals and facets describe
 * the whole filtered set and must not move as the reader pages. So the cost of
 * the page IS the cost of one read, and that is what this measures — each view
 * unfiltered, and each with the filters the toolbar can apply, at two store
 * sizes an order of magnitude apart.
 *
 * NO ASSERTIONS: nothing in this repository gates a PR on wall-clock. The
 * numbers this file produces are a trend, taken by the nightly
 * `.github/workflows/bench.yml` run and re-taken by hand when a read changes.
 * What must HOLD about these reads is asserted elsewhere as a query plan
 * (`test/performance/hot-read-query-plans.test.ts`) and as a ratio across two
 * store sizes (`test/performance/findings-page-scale.test.ts`).
 *
 * WHY THE CORPUS IS SHAPED THE WAY IT IS. The page is sensitive to four axes a
 * default corpus does not exercise, and each one is passed explicitly here:
 *
 *  - **Many rules.** The grouped view groups by rule, so a one-rule corpus
 *    measures every per-group cost against a single bucket. `BENCH_RULES` is
 *    forty rules with a long-tailed weight, the shape an installed pack set
 *    fires in.
 *  - **Repos and host tools.** The locations view folds by repo then file, and
 *    the instance reads filter and facet on the host tool; a corpus carrying
 *    neither folds everything into one bucket and leaves that facet empty.
 *  - **Structural rows.** Every findings read rejects the non-capture audit
 *    rows through a kind predicate, and a real store holds more of those than
 *    captures. One `tool_call` per capture is the measured proportion.
 *  - **Resolutions.** The status column derives from the latest resolution per
 *    key, and an empty `finding_resolution` is the cheapest path through that
 *    join. Half the trackable findings carry one here — a stated assumption
 *    rather than a measurement, chosen so the join costs something.
 *
 * WHY THE CLOCK IS PINNED. The `from` scope filters on a window ending "now",
 * and the generator stamps its events from a fixed 2024 epoch. Left on the wall
 * clock the window sits years past every row and the scoped reads measure an
 * empty scope while reporting a real number.
 */
import { bench, describe } from 'vitest';

import { SqliteFindingsRepository } from '../src/repositories/findings.ts';
import type { CorpusRule } from '../test/helpers/corpus.ts';
import { corpusConnection, seedCaptureCorpus } from '../test/helpers/corpus.ts';
import type { OwnedTempStore } from '../test/helpers/temp-store.ts';
import { createTempStore } from '../test/helpers/temp-store.ts';

/**
 * 1M is absent for the reason `queries.bench.ts` gives: the corpus takes
 * minutes to seed, which is too much for a nightly.
 */
const SCALES = [10_000, 100_000] as const;

const DAY_MS = 86_400_000;

/** Milliseconds between consecutive events — the measured figure. */
const REAL_SPACING_MS = 74_528;

/** Fraction of trackable findings carrying a resolution row — an assumption, stated. */
const BENCH_RESOLUTION_RATE = 0.5;

/** Distinct repositories a `code_change` capture may name. */
const BENCH_REPOS = 12;

/** Host tools a `tool_use` capture may name. */
const BENCH_TOOL_NAMES = ['Bash', 'Read', 'Edit', 'Write', 'WebFetch', 'Grep'] as const;

/** `tool_call` rows per capture — the measured proportion, rounded. */
const BENCH_STRUCTURAL_PER_CAPTURE = 1;

const CATEGORIES: readonly CorpusRule['category'][] = [
  'secret',
  'pii',
  'code_context',
  'code_flaw',
  'phi',
  'financial',
];
const SEVERITIES: readonly CorpusRule['severity'][] = ['critical', 'high', 'medium', 'low'];

/**
 * Forty rules with a long-tailed firing weight: rule `i` fires with weight
 * `1 / (i + 1)`, so the first few dominate the way a real pack set does.
 */
export const BENCH_RULES: readonly CorpusRule[] = Array.from({ length: 40 }, (_, i) => {
  const category = CATEGORIES[i % CATEGORIES.length] ?? 'secret';
  const severity = SEVERITIES[i % SEVERITIES.length] ?? 'low';
  return { ruleId: `${category}/rule-${String(i)}`, category, severity, weight: 1 / (i + 1) };
});

interface Surfaces {
  readonly store: OwnedTempStore;
  readonly findings: SqliteFindingsRepository;
  readonly sessionId: string;
  readonly now: number;
  /** The cursor that fetches the second flat page — minted once, in setup. */
  readonly secondPageCursor: string | null;
  /** The heaviest rule in the corpus — the detail panel's worst realistic case. */
  readonly ruleId: string;
}

const fixtures = new Map<number, Surfaces>();

async function fixtureFor(events: number): Promise<Surfaces> {
  const existing = fixtures.get(events);
  if (existing) return existing;

  const store = createTempStore(`aka-bench-findings-${String(events)}-`);
  const db = store.open();
  const corpus = seedCaptureCorpus(db, {
    events,
    sessions: 200,
    seed: 1,
    spacingMs: REAL_SPACING_MS,
    resolutionRate: BENCH_RESOLUTION_RATE,
    rules: BENCH_RULES,
    actions: ['block', 'redact', 'warn', 'log'],
    repos: BENCH_REPOS,
    toolNames: BENCH_TOOL_NAMES,
    structuralPerCapture: BENCH_STRUCTURAL_PER_CAPTURE,
  });
  const raw = corpusConnection(db);
  const sessionRow = raw
    .prepare(
      `SELECT root_session_id AS id FROM audit_events WHERE root_session_id IS NOT NULL LIMIT 1`,
    )
    .get() as { id: string } | undefined;

  const findings = new SqliteFindingsRepository(raw);
  const firstPage = await findings.listFindingInstances({});
  // The type carrying the most findings: the detail panel's worst case, and the
  // one the old bounded preview was hiding the cost of.
  const types = (await findings.listFindingTypes({})).items;
  const heaviest = [...types].sort((a, b) => b.instanceCount - a.instanceCount)[0]?.id ?? '';
  const surfaces: Surfaces = {
    store,
    findings,
    sessionId: sessionRow?.id ?? '',
    now: corpus.endsAt,
    secondPageCursor: firstPage.nextCursor,
    ruleId: heaviest,
  };
  fixtures.set(events, surfaces);
  return surfaces;
}

process.on('exit', () => {
  for (const { store } of fixtures.values()) {
    try {
      store.destroy();
    } catch {
      // Teardown of a benchmark fixture; a failure here has nothing to report to.
    }
  }
});

const PART_OPTIONS = { time: 0, iterations: 5, warmupIterations: 1, warmupTime: 0 };

/** Every read the page can issue, in the order the toolbar exposes them. */
const READS: readonly [string, (s: Surfaces) => Promise<unknown>][] = [
  // --- by-type view (the default): the type list, then the selected type's
  // findings. Both are page loads, so both are measured — the second is what
  // the old grouped read used to fold into the first as a bounded preview.
  ['types: default', (s) => s.findings.listFindingTypes({})],
  ['types: q', (s) => s.findings.listFindingTypes({ q: 'module-1' })],
  ['types: severity', (s) => s.findings.listFindingTypes({ severity: ['critical'] })],
  ['types: status', (s) => s.findings.listFindingTypes({ status: ['open'] })],
  ['types: session', (s) => s.findings.listFindingTypes({ sessionId: s.sessionId })],
  [
    'types: from 30d',
    (s) => s.findings.listFindingTypes({ from: new Date(s.now - 30 * DAY_MS).toISOString() }),
  ],
  [
    'types: selected rule → findings',
    (s) => s.findings.listFindingInstances({ subtype: [s.ruleId] }),
  ],
  // --- flat view -------------------------------------------------------------
  ['flat: first page', (s) => s.findings.listFindingInstances({})],
  [
    'flat: second page',
    (s) =>
      s.findings.listFindingInstances(
        s.secondPageCursor === null ? {} : { cursor: s.secondPageCursor },
      ),
  ],
  ['flat: severity', (s) => s.findings.listFindingInstances({ severity: ['critical'] })],
  ['flat: tool', (s) => s.findings.listFindingInstances({ tool: ['Bash'] })],
  ['flat: q', (s) => s.findings.listFindingInstances({ q: 'module-1' })],
  ['flat: status', (s) => s.findings.listFindingInstances({ status: ['open'] })],
  // --- locations view --------------------------------------------------------
  ['locations: default', (s) => s.findings.listFindingLocations({})],
  ['locations: severity', (s) => s.findings.listFindingLocations({ severity: ['critical'] })],
];

for (const events of SCALES) {
  describe(`/findings at ${events.toLocaleString('en-US')} events`, () => {
    for (const [name, run] of READS) {
      bench(
        name,
        async () => {
          await run(await fixtureFor(events));
        },
        {
          ...PART_OPTIONS,
          setup: async () => {
            await fixtureFor(events);
          },
        },
      );
    }
  });
}
