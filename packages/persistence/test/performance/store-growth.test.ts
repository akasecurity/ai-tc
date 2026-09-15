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
 * (An `aka.db.pre-drop.<ts>.<rand>.bak` — the snapshot a migration takes when
 * the legacy drop would destroy rows, about half a megabyte — is NOT part of
 * this. `settledDbBytes` stats `aka.db` alone, so such a backup is a sibling
 * file outside every number here, and a store built by these fixtures writes
 * none at all. It matters for an at-rest scan of the directory, not for
 * growth.)
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
 * Measured at the same 20k events, one enclosing transaction leaves a log nearly
 * four times the size autocommit settles at (both figures are beside
 * `MEASURED_SETTLED_WAL_BYTES`); the fixture generator's own 1M-event
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
 * The band the marginal cost must land in: ±15% of a measured 1,048.6 B/event
 * for the generator's 240-character events.
 *
 * TIGHT, and it can be, because this is not a timing measurement. The corpus is
 * deterministic and so is SQLite's page allocation, so the figure is
 * byte-identical run to run — two consecutive runs produced 4,956,160 B at 5k
 * and 9,469,952 B at 10k, the same integers each time. Nothing here can flake
 * the way a wall-clock bound does, so the band is sized to catch a regression
 * rather than to survive one.
 *
 * **The centre is a property of the CORPUS AND THE SCHEMA, not of an event**, so
 * it is retaken whenever either moves — not only when the corpus size does.
 * Measured at three consecutive decades: 902.8 B/event across 2.5k→5k, 902.8
 * across 5k→10k, 923.2 across 10k→20k. The slope still creeps as the store
 * grows, ~2.3% over that range.
 *
 * **What moved it last was the SCHEMA**, which is why this paragraph now says
 * "and the schema": migration 0029 adds `idx_audit_capture_rollup`, a partial
 * covering index over (event_type, started_at, repo, id) for the four capture
 * kinds, and an index is bytes per row like anything else. The marginal went
 * 902.8 → 1,048.6 — about 146 B/event, or 16% — which is just past the OLD
 * ceiling of 1,038.2, and that is how it announced itself. This is the index
 * being paid for rather than a regression: it is what lets the /security page's
 * rollups answer from the index instead of walking each row's overflow chain
 * past a `code_change` body. Both figures are byte-identical across runs, as
 * the paragraph above promises.
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
 * when the centre moved rather than scaled forward from the old figure. It is
 * now planted as a SECOND BODY on every event — doubling what `content` is given
 * — rather than as a second copy written into `attributes`, which is the form
 * this paragraph used to describe and which no longer plants anything at all:
 * `metadata` is parsed by `EventMetadata` before the row is written, so Zod
 * strips the unknown key and the "mutated" corpus measures 1,046.1 B/event,
 * within 0.3% of the unmutated centre. That is a control which silently tests
 * nothing. Planted as a second body it reads 1,364.0 B/event and fails the
 * 1,205.9 ceiling above with 13% to spare. Replant it, rather than trusting
 * this paragraph, the next time the pair, the corpus or the schema changes —
 * and check the planted form still survives validation, which is the trap that
 * ate the last one.
 *
 * The 15% is for cross-platform slack, not for noise: a SQLite build with a
 * different default page size would shift the figure, and this should fail
 * loudly and be given a per-platform note rather than be widened until it says
 * nothing. The floor guards the other direction — a slope that COLLAPSED means
 * the corpus stopped writing what it claims to, and a growth test over a store
 * that is not growing proves nothing.
 */
const MEASURED_MARGINAL_BYTES_PER_EVENT = 1048.6;
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
 * The log the WAL case's loop leaves, read after its last commit: 20,000
 * autocommit captures on a templated store at the default autocheckpoint and
 * page size.
 *
 * The ceiling is placed against a second outcome that nothing here measures:
 * the same writes inside ONE enclosing transaction, where no checkpoint can run,
 * grow the log to 16,203,992 B read after the COMMIT, or 15,388,232 B read just
 * before it — the commit's own frames are the difference, so re-take it at the
 * same point. Durability moves neither figure: on an unmigrated store each read
 * identically under FULL and OFF, on Linux and macOS.
 *
 * Nothing asserts either number, so re-take both when the schema, the event or
 * the fixture's store changes; the ceiling is the only thing derived from them.
 */
const MEASURED_SETTLED_WAL_BYTES = 4_223_032;

/**
 * Twice the settled log, which leaves the unbounded case still more than 1.8
 * times over it — so the bound separates two measured outcomes rather than
 * sitting at a round number.
 */
const MAX_WAL_BYTES = 2 * MEASURED_SETTLED_WAL_BYTES;

/**
 * SQLite's compiled-in `wal_autocheckpoint` and `page_size`. The settled log is
 * roughly their product and `openWithPragmas` sets neither, so a node:sqlite
 * build with a smaller default of either settles lower and passes the ceiling
 * without being the store it was measured on. Read back in the positive control.
 */
const DEFAULT_AUTOCHECKPOINT_PAGES = 1000;
const DEFAULT_PAGE_SIZE_BYTES = 4096;

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
  // Templated: the slope is taken between two stores, so whatever the template
  // changes about the base cancels — and both sizes measured byte-identical to
  // an unmigrated store's anyway.
  const store = createTempStore('aka-growth-', { migrated: true });
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
// point, since a checkpoint cannot run inside one — and it overran its own 180 s
// setup ceiling on that runner while every one of those commits was an fsync, on
// the platform that charges most for it. The leg is SHARED: `findings-flat.test.ts`
// timed out alongside it at the config's 20 s while having nothing to do with
// this file. The loop no longer fsyncs (see the `synchronous` note below), but
// what it costs on that leg without them has not been measured, so the skip
// stands until it is.
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
  let store: OwnedTempStore | undefined;
  let peak = 0;
  let written = 0;
  let pragmas: Record<string, number | undefined> = {};

  beforeAll(() => {
    // Templated: this case measures the log a capture loop leaves, not the open
    // path, and the settled figure is byte-identical either way. It also spares
    // the migration replay on open.
    store = createTempStore('aka-wal-', { migrated: true });
    const db = store.open();
    const raw = corpusConnection(db);
    const walFile = join(store.dataDir, 'aka.db-wal');

    // Durability is the one setting this fixture turns down, and the product
    // does not share it: `openWithPragmas` leaves `synchronous` at node:sqlite's
    // compiled SQLITE_DEFAULT_WAL_SYNCHRONOUS=2, where every commit below fsyncs
    // the log, so the setup cost the runner's fsync latency times twenty
    // thousand. Counted on an unmigrated store, a run made 20,916 fsyncs from
    // open to close, all but 53 of them in this loop. Reproduced with a fixed
    // delay injected into fsync, the loop took 277 s at 9 ms an fsync, past the
    // ceiling above; at OFF it makes no fsync at all and took 1.5 s under the
    // same delay. NORMAL still syncs at every checkpoint — 916 fsyncs in that
    // run — which is 100 s at 100 ms an fsync.
    //
    // What that moves is the cost, not the quantity asserted: the
    // autocheckpoint counts frames, and a frame is the same bytes synced or
    // not, so both measurements beside MEASURED_SETTLED_WAL_BYTES read
    // identically under FULL and OFF. Every pragma the result depends on is
    // read back rather than trusted — including this one, because SQLite
    // resolves an unrecognised `synchronous` value to NORMAL without raising.
    raw.exec('PRAGMA synchronous = OFF');
    const pragma = (name: string): number | undefined =>
      (raw.prepare(`PRAGMA ${name}`).get() as Record<string, number | undefined>)[name];
    pragmas = {
      synchronous: pragma('synchronous'),
      walAutocheckpoint: pragma('wal_autocheckpoint'),
      pageSize: pragma('page_size'),
    };

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
      // At the default `journal_size_limit` a checkpoint rewinds the log and
      // reuses the file rather than truncating it, so its size never falls and
      // the read after the loop is already the peak. These reads matter only
      // for a log that DOES shrink — a size limit, or a TRUNCATE checkpoint
      // landing mid-loop — which the final read alone would report as small.
      if (i % 500 === 0) peak = Math.max(peak, sizeOr0(walFile));
    }
    peak = Math.max(peak, sizeOr0(walFile));

    written = (raw.prepare(`SELECT COUNT(*) AS n FROM audit_events`).get() as { n: number }).n;
  }, SETUP_TIMEOUT_MS);

  afterAll(() => {
    // Undefined when `createTempStore` itself threw, which removes its own tree
    // first; a TypeError here would only speak over that failure.
    store?.destroy();
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
    // The two defaults the settled log is a product of, and the durability the
    // setup's cost rests on. A smaller autocheckpoint or page settles the log
    // lower and passes the ceiling for a store it was not measured on; a
    // `synchronous` that fell back from OFF would pass every other assertion
    // here while bringing the setup's fsyncs back.
    expect(pragmas, 'the fixture connection is not configured as measured').toEqual({
      synchronous: 0,
      walAutocheckpoint: DEFAULT_AUTOCHECKPOINT_PAGES,
      pageSize: DEFAULT_PAGE_SIZE_BYTES,
    });
  });

  it('stays bounded while the product writes one transaction per capture', () => {
    expect(
      peak,
      `peak -wal was ${(peak / 1024 / 1024).toFixed(1)} MiB over ${String(WAL_EVENTS)} committed captures`,
    ).toBeLessThan(MAX_WAL_BYTES);
  });
});
