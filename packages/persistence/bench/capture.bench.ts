/**
 * The store's WRITE path, and its OPEN path, at a stated store size.
 *
 * Both sit inside the hook's 10 s budget on every single tool call, and a hook
 * that blows that budget is killed — which the harness reads as "no opinion",
 * so the tool call goes through unscanned. Performance here is a detection
 * property, not a comfort one, and the number that matters is whether either
 * cost grows with the store. A per-call cost that is flat in the table size can
 * be budgeted once; one that is not turns every install into a clock counting
 * down to a silent detection gap.
 *
 * Both are flat. Measured on arm64 macOS, Node 24, against corpora built by
 * `src/test-fixtures/generate.ts`:
 *
 * | store size | `recordCapture` | `openLocalDatabase` |
 * | ---------- | --------------: | ------------------: |
 * | 10k events |       0.0958 ms |           0.5883 ms |
 * | 100k       |        0.088 ms |             0.56 ms |
 * | 1M         |        0.076 ms |             0.55 ms |
 *
 * The 10k row is the tinybench MEAN from `pnpm bench`; the other two are the
 * MEDIAN of the scale sweep (n=200 captures, n=20 opens). Different statistics
 * because they come from different harnesses — the point is the flatness, which
 * holds either way, not a fourth significant figure.
 *
 * Against the budgets those are ≤ 30 ms for a capture and ≤ 100 ms for an open:
 * roughly 165× and 125× of headroom at a million events. `test/performance/`
 * carries those two as assertions at a size a test tier can afford; this file
 * is the trend, and the only place the 1M end is exercised at all.
 *
 * WHY THE CORPUS IS BUILT OUTSIDE THE TIMED REGION. It is setup, not the thing
 * measured, and it is five orders of magnitude more expensive than the call
 * under test — a 100k corpus takes about ten seconds against a 0.086 ms
 * capture — so folding it in would measure the generator and report it as the
 * write path. tinybench's hooks are
 * per-CYCLE, so the store is built once in module scope and every iteration
 * writes one more row into it. That is a real drift (the table grows by however
 * many iterations run) and it is bounded and directional: the store ends at most
 * a few thousand rows past where it started, which at these scales does not
 * move the number — the table above is what says so, since a cost that noticed
 * a few thousand rows could not have been flat from 10k to 1M.
 *
 * NO ASSERTIONS, and there should be none: nothing in this repository gates a
 * PR on wall-clock. This reports a trend; the budgets live next door.
 */
import type { IngestEvent } from '@akasecurity/schema';
import { bench, describe } from 'vitest';

import type { LocalDatabase } from '../src/database.ts';
import { openLocalDatabase } from '../src/database.ts';
import { CORPUS_EPOCH_MS, seedCaptureCorpus } from '../test/helpers/corpus.ts';
import type { OwnedTempStore } from '../test/helpers/temp-store.ts';
import { createTempStore } from '../test/helpers/temp-store.ts';

/**
 * The two sizes this file runs at.
 *
 * 1M is deliberately absent: the corpus alone takes 10.7 minutes to
 * build, which is more than a nightly job should spend on one bench file. The
 * 1M column in the table above was taken by hand against a store built once —
 * re-measure it that way rather than by adding a scale here.
 */
const SCALES = [10_000, 100_000] as const;

/** A distinct capture per iteration — see the contentHash note below. */
function makeEvent(seq: number): IngestEvent {
  return {
    id: `ffffffff-0000-4000-8000-${String(seq).padStart(12, '0')}`,
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: new Date(CORPUS_EPOCH_MS + seq * 1_000).toISOString(),
    // The capture row is content-addressed on (session, hash, path). A constant
    // hash would make every iteration after the first an upsert onto ONE row —
    // a cheaper operation than the insert being measured, and one that would
    // report the write path as faster than it is while the table never grew.
    contentHash: `bench-capture-${String(seq)}`,
    content: 'refactor the session handler so a retry never reopens the store',
    metadata: { sessionId: '22222222-2222-4222-8222-222222222222' },
  };
}

interface Fixture {
  readonly store: OwnedTempStore;
  readonly db: LocalDatabase;
  readonly dataDir: string;
}

const fixtures = new Map<number, Fixture>();

function fixtureFor(events: number): Fixture {
  const existing = fixtures.get(events);
  if (existing) return existing;
  const store = createTempStore(`aka-bench-capture-${String(events)}-`);
  const db = store.open();
  // Throws if the rows are not on disk, so a store that silently refused every
  // write cannot be benchmarked as a fast one.
  seedCaptureCorpus(db, { events, sessions: 200, seed: 1 });
  const fixture: Fixture = { store, db, dataDir: store.dataDir };
  fixtures.set(events, fixture);
  return fixture;
}

// tinybench has no "after all files" hook, so the stores are removed when the
// process ends. `createTempStore` roots them under the OS temp dir, so a killed
// run leaks a directory the OS reaps rather than anything in the tree.
process.on('exit', () => {
  for (const { store } of fixtures.values()) {
    try {
      store.destroy();
    } catch {
      // Teardown of a benchmark fixture; a failure here has nothing to report to.
    }
  }
});

describe('recordCapture at a stated store size', () => {
  // Samples are tens of microseconds, so the defaults would take tens of
  // thousands of them and grow the table enough to matter. A fixed count keeps
  // the drift bounded and stated.
  const options = { time: 0, iterations: 2_000, warmupIterations: 200, warmupTime: 0 };

  for (const events of SCALES) {
    let seq = 0;
    bench(
      `${events.toLocaleString('en-US')} events already stored`,
      () => {
        seq += 1;
        fixtureFor(events).db.recordCapture(makeEvent(seq), []);
      },
      {
        ...options,
        // Built in the hook rather than at module load so the cost of seeding
        // is not attributed to whichever bench happens to run first.
        setup: () => {
          fixtureFor(events);
        },
      },
    );
  }
});

describe('openLocalDatabase at a stated store size', () => {
  // Migrations are already applied on these stores, so this is the steady-state
  // open every hook process pays: the pragmas, the ledger check, twenty-odd
  // repository constructions and their eager prepares, and `seedDefaults`.
  const options = { time: 0, iterations: 200, warmupIterations: 20, warmupTime: 0 };

  for (const events of SCALES) {
    bench(
      `${events.toLocaleString('en-US')} events already stored`,
      () => {
        const handle = openLocalDatabase(fixtureFor(events).dataDir);
        handle.close();
      },
      {
        ...options,
        setup: () => {
          fixtureFor(events);
        },
      },
    );
  }
});
