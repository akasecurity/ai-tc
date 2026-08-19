/**
 * How much disk the store takes per event, and whether the write-ahead log
 * stays bounded while it fills.
 *
 * Both are SIZES, not durations, which is what makes them assertable. Every
 * timing budget in this package lives in a benchmark precisely because a CI
 * runner's wall clock is too noisy to gate on; a byte count is not — SQLite
 * writes the same pages on a loaded machine as on an idle one, so a ceiling here
 * fails for a real reason or not at all.
 *
 * ## Growth is measured MARGINALLY
 *
 * Dividing a fresh store's size by its event count overstates the per-event
 * cost, because `aka.db` carries a fixed overhead that has nothing to do with
 * how many events are in it: the schema, its indexes, the default policies, and
 * page granularity. The measured naive figure falls from 895 B/event at 10k to
 * 826 B at 1M purely as that constant is amortised away.
 *
 * (The `aka.db.pre-drop.<ts>.<rand>.bak` a migration leaves in the data dir —
 * about half a megabyte, once per store — is NOT part of this. `settledDbBytes`
 * stats `aka.db` alone, so the backup is a sibling file outside every number
 * here. It matters for an at-rest scan of the directory, not for growth.)
 *
 * So the property asserted is the SLOPE — `(bytes(2N) − bytes(N)) / N` — which
 * cancels the constant and is the number that answers "what does another year
 * of use cost". A test written against the naive figure would have to be
 * re-tuned every time the fixed overhead moved, and would drift toward
 * accepting whatever the slope had become.
 *
 * ## The WAL is bounded under the write pattern the PRODUCT uses
 *
 * `openWithPragmas` never sets `wal_autocheckpoint`, which reads like an
 * unbounded `-wal`. It is not: SQLite's own default of 1000 pages still applies,
 * so at the store's 4 KiB page size a checkpoint fires about every 4 MiB and the
 * log settles there. That is asserted below — and asserted at an event count
 * high enough that a log which never checkpointed would be several times over
 * the ceiling, so the assertion distinguishes "bounded" from "small so far".
 *
 * The bound depends on the writes COMMITTING, which is the one thing that makes
 * this worth pinning rather than assuming: a checkpoint cannot run inside a
 * transaction, so a single long one grows the log by its whole page footprint.
 * Measured at the same 20k events, autocommit peaks at 4,198,312 B while one
 * enclosing transaction peaks at 12,219,952 B; the fixture generator's own 1M-event
 * transaction grows the log by its whole page footprint, which runs to hundreds of
 * megabytes. Nothing on the capture path does that — every
 * `recordCapture` is its own transaction and every hook is its own process — but
 * a future batch importer would, and this comment is the warning.
 */
import { statSync } from 'node:fs';
import { join } from 'node:path';

import type { IngestEvent } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { CORPUS_EPOCH_MS, corpusConnection, seedCaptureCorpus } from '../helpers/corpus.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

/**
 * The two scales the slope is taken across. Small enough to keep the file a
 * couple of seconds, far enough apart that the fixed overhead is a minority of
 * the difference.
 *
 * They came down from 10k/20k, which cost 11.6 s to seed here against 2.7 s for
 * this pair (fastest of two, arm64 macOS / Node 24.18) — and several times that
 * on the Windows leg, which is shared, and where the corpora this file and
 * `scale-budgets.test.ts` write are the two largest single pieces of work the
 * package does. Nothing about the property needed the larger pair: it is a
 * SLOPE, and a slope is stated as well by one decade as by another.
 */
const BASE_EVENTS = 5_000;
const DOUBLE_EVENTS = 10_000;

/**
 * The band the marginal cost must land in: ±15% of a measured 902.8 B/event for
 * the generator's 240-character events.
 *
 * TIGHT, and it can be, because this is not a timing measurement. The corpus is
 * deterministic and so is SQLite's page allocation, so the figure is
 * byte-identical run to run — two consecutive runs produced 4,956,160 B at 5k
 * and 9,469,952 B at 10k, the same integers each time. Nothing here can flake
 * the way a wall-clock bound does, so the band is sized to catch a regression
 * rather than to survive one.
 *
 * **The centre is a property of the CORPUS, not of an event**, so it is retaken
 * whenever anything about the corpus moves — not only its size. Measured at
 * three consecutive decades: 902.8 B/event across 2.5k→5k, 902.8 across 5k→10k,
 * 923.2 across 10k→20k. The slope still creeps as the store grows, ~2.3% over
 * that range.
 *
 * **What moved it last was the generator's finding RATE, not its size**, and that
 * is the case this paragraph exists to stop being learned again. The rate went
 * from 0.1 to a measured 0.33 (see `DEFAULT_FINDING_RATE`), so every event now
 * carries about three times the finding rows, and the marginal went 797.9 →
 * 902.8. Against the OLD centre's 917.6 ceiling that is a pass — by 1.6%. So the
 * band did not catch a 13% growth regression and would not have caught the next
 * one either; it would simply have started failing on some unrelated commit, at
 * which point the obvious-looking fix is to widen it. A centre nobody re-measured
 * drifts off the measurement it is supposed to bracket, one change at a time, and
 * reads as green throughout.
 *
 * The three decades above were measured at the current rate. The figures the old
 * centre rested on (791.3 / 797.9 / 818.4) described a corpus with a third of
 * the findings and are retracted rather than kept for comparison.
 *
 * A band this narrow was chosen after a loose one failed to earn its place: at
 * a 1,800 B ceiling, a mutation that wrote a SECOND copy of every event's
 * content into `attributes` — a real ~30% storage regression — still passed. The
 * ceiling has to sit below the smallest regression worth catching, not below the
 * absurd ones.
 *
 * That mutation is what re-earns the band at THIS centre, and it was replanted
 * when the centre moved rather than scaled forward from the old figure: it reads
 * 1,214.1 B/event (6,516,736 B at 5k against 12,587,008 B at 10k) and fails the
 * 1,038.2 ceiling above. Scaling the old 1,129.7 by the centre's own movement
 * would have predicted 1,282.0 and been wrong by 5%, which is the reason to
 * replant rather than extrapolate. Replant it, rather than trusting this
 * paragraph, the next time either the pair or the corpus changes.
 *
 * The 15% is for cross-platform slack, not for noise: a SQLite build with a
 * different default page size would shift the figure, and this should fail
 * loudly and be given a per-platform note rather than be widened until it says
 * nothing. The floor guards the other direction — a slope that COLLAPSED means
 * the corpus stopped writing what it claims to, and a growth test over a store
 * that is not growing proves nothing.
 */
const MEASURED_MARGINAL_BYTES_PER_EVENT = 902.8;
const MARGINAL_TOLERANCE = 0.15;
const MIN_MARGINAL_BYTES_PER_EVENT = MEASURED_MARGINAL_BYTES_PER_EVENT * (1 - MARGINAL_TOLERANCE);
const MAX_MARGINAL_BYTES_PER_EVENT = MEASURED_MARGINAL_BYTES_PER_EVENT * (1 + MARGINAL_TOLERANCE);

/**
 * The ceiling on the WRITES each case needs, distinct from anything asserted.
 *
 * Both corpora and the 20k-commit loop are setup: they take seconds here and
 * several times that on the slowest CI leg, and a synchronous body cannot be
 * interrupted — it runs to completion and is then reported as a timeout, which
 * reads as a size regression and is not one. So the writing happens in
 * `beforeAll` under this, and each `it()` holds only arithmetic and assertions
 * under the config's own budget. Nothing measures against this number.
 */
const SETUP_TIMEOUT_MS = 180_000;

/** Autocommit writes for the WAL case — the shape a hook produces. */
const WAL_EVENTS = 20_000;

/**
 * 8 MiB: about double the 4,198,312 B an autocheckpointing log settles at, and
 * comfortably below the 12,219,952 B the same writes reach with the checkpoint
 * suppressed. Both numbers were measured at this event count, so the ceiling
 * sits between two known outcomes rather than at a round number.
 */
const MAX_WAL_BYTES = 8 * 1024 * 1024;

/** A checkpointed store's own file size, with the sidecars flushed into it. */
function settledDbBytes(dataDir: string, raw: { exec: (sql: string) => void }): number {
  raw.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  return statSync(join(dataDir, 'aka.db')).size;
}

function sizeOr0(file: string): number {
  try {
    return statSync(file).size;
  } catch {
    return 0;
  }
}

function corpusBytes(events: number): number {
  const store = createTempStore('aka-growth-');
  try {
    const db = store.open();
    seedCaptureCorpus(db, { events, sessions: 50, seed: 1 });
    return settledDbBytes(store.dataDir, corpusConnection(db));
  } finally {
    store.destroy();
  }
}

describe('store growth per event', () => {
  let small = 0;
  let large = 0;

  beforeAll(() => {
    small = corpusBytes(BASE_EVENTS);
    large = corpusBytes(DOUBLE_EVENTS);
  }, SETUP_TIMEOUT_MS);

  it('the marginal cost of an event is linear and within the measured band', () => {
    // A store that did not grow at all would make every ratio below degenerate,
    // and is the shape a broken corpus takes.
    expect(large, 'the larger corpus is not larger on disk').toBeGreaterThan(small);

    const marginal = (large - small) / (DOUBLE_EVENTS - BASE_EVENTS);
    expect(
      marginal,
      `marginal growth was ${marginal.toFixed(1)} B/event (${String(small)} B at ${String(BASE_EVENTS)}, ${String(large)} B at ${String(DOUBLE_EVENTS)})`,
    ).toBeGreaterThan(MIN_MARGINAL_BYTES_PER_EVENT);
    expect(
      marginal,
      `marginal growth was ${marginal.toFixed(1)} B/event (${String(small)} B at ${String(BASE_EVENTS)}, ${String(large)} B at ${String(DOUBLE_EVENTS)})`,
    ).toBeLessThan(MAX_MARGINAL_BYTES_PER_EVENT);
  });
});

// Skipped on Windows on COST, not because the property differs there. The
// `beforeAll` below commits 20,000 separate transactions — that is the whole
// point, since a checkpoint cannot run inside one — and every commit is an
// fsync on the platform that charges most for it. It overran its own 180 s
// setup ceiling on that runner, and the leg is SHARED: `findings-flat.test.ts`
// timed out alongside it at the config's 20 s while having nothing to do with
// this file.
//
// What is asserted is SQLite's page arithmetic — the default 1000-page
// autocheckpoint against a 4 KiB page — which is a property of the engine, not
// of the filesystem underneath it. So the Linux and macOS legs cover it, the
// same way the file-cap case in `plugin-sdk`'s walk tier and this package's own
// `/security` omission are argued. Lowering WAL_EVENTS instead was the
// alternative and is worse: the count is what makes a log that never
// checkpointed land several times over the ceiling, so cutting it weakens the
// assertion everywhere to buy coverage on one platform.
const describeWal = describe.skipIf(process.platform === 'win32');

describeWal('write-ahead log growth under sustained writes', () => {
  let store: OwnedTempStore;
  let peak = 0;
  let written = 0;

  beforeAll(() => {
    store = createTempStore('aka-wal-');
    const db = store.open();
    const walFile = join(store.dataDir, 'aka.db-wal');

    for (let i = 0; i < WAL_EVENTS; i += 1) {
      // No enclosing transaction: each call commits on its own, which is what
      // a hook does and what lets the autocheckpoint fire at all.
      const event: IngestEvent = {
        id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
        sourceTool: 'claude-code',
        kind: 'prompt',
        occurredAt: new Date(CORPUS_EPOCH_MS + i * 1_000).toISOString(),
        // Content-addressed on (session, hash, path): a shared hash would
        // collapse every write onto one row, and a log that stayed small
        // because nothing was written would pass this test for the wrong
        // reason.
        contentHash: `wal-${String(i)}`,
        content:
          'refactor the session handler so a retry never reopens the store and the walk moves off thread before the deadline returns',
        metadata: { sessionId: '11111111-1111-4111-8111-111111111111' },
      };
      db.recordCapture(event, []);
      if (i % 500 === 0) peak = Math.max(peak, sizeOr0(walFile));
    }
    peak = Math.max(peak, sizeOr0(walFile));

    written = (
      corpusConnection(db).prepare(`SELECT COUNT(*) AS n FROM audit_events`).get() as { n: number }
    ).n;
  }, SETUP_TIMEOUT_MS);

  afterAll(() => {
    store.destroy();
  });

  it('actually wrote, and actually used the log', () => {
    // The positive control. The bound below is an upper one, and a store that
    // refused every write — or one whose sidecar moved and left `sizeOr0`
    // reading a missing file as 0 — satisfies it perfectly.
    //
    // `>=`, not `>`: the table also holds the session root, so a strict
    // comparison passes by exactly one row and would flip red if the product
    // stopped planting it — a failure that says nothing about the log.
    expect(written, 'no rows were written, so the log had nothing to bound').toBeGreaterThanOrEqual(
      WAL_EVENTS,
    );
    expect(peak, 'the -wal file never appeared; this measured nothing').toBeGreaterThan(0);
  });

  it('stays bounded while the product writes one transaction per capture', () => {
    expect(
      peak,
      `peak -wal was ${(peak / 1024 / 1024).toFixed(1)} MiB over ${String(WAL_EVENTS)} committed captures`,
    ).toBeLessThan(MAX_WAL_BYTES);
  });
});
