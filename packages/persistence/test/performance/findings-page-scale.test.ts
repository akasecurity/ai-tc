/**
 * The `/findings` reads whose cost must NOT grow with the store, asserted as a
 * ratio across two store sizes — the same experiment `security-page-scale.test.ts`
 * runs for `/security`, and for the same reasons, which are not repeated here.
 *
 * ## Which reads can be flat at all
 *
 * The unscoped findings reads are linear in the store BY DESIGN: totals and
 * facets describe every finding in scope, so an unscoped `listGroupedFindings`
 * has to visit every finding to count them. That read is the CONTROL here — it
 * is asserted to GROW, and if it goes flat the harness has stopped measuring
 * growth and every other case in this file is worthless.
 *
 * What CAN be flat is a SCOPED read. `?session=` narrows every one of the three
 * views to one session's findings, and a session's size is a property of the
 * session rather than of the store — so with the sessions held at a fixed size
 * (`EVENTS_PER_SESSION`), a ten-fold larger store must not make the session's
 * own reads cost more. That is the property a plan test cannot state (every
 * step of a plan can read as a SEARCH and still walk the store — `mttrTrend`
 * did exactly that) and a benchmark cannot gate.
 *
 * ## What holds the answer fixed
 *
 * Two things scale with events and each is pinned back:
 *
 *  - **Sessions.** `sessions = events / EVENTS_PER_SESSION`, so the number of
 *    sessions grows and each session stays the same size.
 *  - **Resolutions.** The grouped read joins a derived table over the WHOLE
 *    resolution table before its scope predicate can narrow anything, so a
 *    resolution count that scaled with events would grow the scoped read for a
 *    legitimate reason. `resolutionRate` is scaled by 1/events to hold it near
 *    `RESOLUTION_TARGET`, and the two counts are asserted within tolerance.
 *
 * ## The estimator and the bound
 *
 * Fastest-of-n, as a ratio, for the reasons `scale-budgets.test.ts` sets out:
 * a shared runner does not get uniformly slower, it gets preempted, and the
 * minimum is the one statistic a preempted sample cannot inflate.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { SqliteFindingsRepository } from '../../src/repositories/findings.ts';
import type { CorpusRule, GeneratedCaptureCorpus } from '../helpers/corpus.ts';
import { corpusConnection, seedCaptureCorpus } from '../helpers/corpus.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

const SMALL_EVENTS = 2_000;
const LARGE_EVENTS = 20_000;

/** Events per session at BOTH sizes — what makes a session-scoped read's answer fixed. */
const EVENTS_PER_SESSION = 10;

/** Real per-event spacing, measured on a real store; keeps timestamps plausible. */
const REAL_SPACING_MS = 74_528;

/** Resolutions both corpora carry, so only the store grows. */
const RESOLUTION_TARGET = 120;

/** Trackable findings per event, used only to aim `resolutionRate` at the target. */
const TRACKABLE_PER_EVENT = 0.08;

/** How far the two resolution counts may differ before the experiment is void. */
const RESOLUTION_TOLERANCE = 0.35;

/** A flat read may not cost more than this multiple at ten times the store. */
const FLATNESS_CEILING = 3;

/** The control must exceed this, or the harness is not measuring growth. */
const CONTROL_FLOOR = 2;

/**
 * A gross-regression backstop — a cost that becomes 500 ms at EVERY size keeps
 * a ratio of 1.0. Sized far above the measured single-digit milliseconds.
 */
const GROSS_REGRESSION_MS = 500;

const SAMPLES = 25;

/** The hook's ceiling — nothing is measured against it; see security-page-scale.test.ts. */
const SEED_TIMEOUT_MS = 240_000;

const CATEGORIES: readonly CorpusRule['category'][] = ['secret', 'pii', 'code_context', 'phi'];
const SEVERITIES: readonly CorpusRule['severity'][] = ['critical', 'high', 'medium', 'low'];

/** A dozen rules with a long-tailed weight, so the grouped read has groups to fold. */
const RULES: readonly CorpusRule[] = Array.from({ length: 12 }, (_, i) => {
  const category = CATEGORIES[i % CATEGORIES.length] ?? 'secret';
  const severity = SEVERITIES[i % SEVERITIES.length] ?? 'low';
  return { ruleId: `${category}/rule-${String(i)}`, category, severity, weight: 1 / (i + 1) };
});

function fastest(samples: number[]): number {
  return Math.min(...samples);
}

/**
 * `SAMPLES` timings of the read's SYNCHRONOUS work. Every method here runs its
 * SQL synchronously and returns an already-resolved promise, so the elapsed
 * time around the bare call is the whole of the work — see the note of the same
 * name in security-page-scale.test.ts for why the rejection is caught and why
 * that catch is empty.
 */
function measure(fn: () => Promise<unknown>): number[] {
  const out: number[] = [];
  for (let i = 0; i < SAMPLES; i += 1) {
    const started = performance.now();
    void fn().catch(() => {
      // The awaited call in `seedAndMeasure` reports a broken read; this only
      // keeps a rejection from being unhandled.
    });
    out.push(performance.now() - started);
  }
  return out;
}

interface Scale {
  readonly corpus: GeneratedCaptureCorpus;
  /** Rows each read MATCHED — a read that matches nothing measures nothing. */
  readonly matched: Record<string, number>;
  readonly samples: Record<string, number[]>;
}

const READS = ['groupedInSession', 'flatInSession', 'locationsInSession', 'groupedAll'] as const;
type ReadName = (typeof READS)[number];

/** The three session-scoped reads that must stay flat; the fourth is the control. */
const FLAT_READS: readonly ReadName[] = ['groupedInSession', 'flatInSession', 'locationsInSession'];

async function seedAndMeasure(store: OwnedTempStore, events: number): Promise<Scale> {
  const db = store.open();
  const corpus = seedCaptureCorpus(db, {
    events,
    sessions: events / EVENTS_PER_SESSION,
    spacingMs: REAL_SPACING_MS,
    resolutionRate: Math.min(1, RESOLUTION_TARGET / (events * TRACKABLE_PER_EVENT)),
    rules: RULES,
    actions: ['block', 'redact', 'warn', 'log'],
    repos: 6,
    toolNames: ['Bash', 'Read', 'Edit'],
    structuralPerCapture: 1,
  });
  const raw = corpusConnection(db);
  // Both sizes measured in the same STATE — the seed's single transaction
  // leaves a log proportional to the corpus, and a checkpoint cannot run inside
  // one. `scale-budgets.test.ts` explains the ratio this once broke.
  raw.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  const findings = new SqliteFindingsRepository(raw);

  // The session with the MOST findings, so the scoped reads have something to
  // count and the vacuity check below can fire. Its size is bounded by
  // EVENTS_PER_SESSION whichever session it is, which is what keeps the scoped
  // answer fixed across the two corpora.
  const sessionRow = raw
    .prepare(
      `SELECT e.root_session_id AS id, count(*) AS n
         FROM inspection_findings f JOIN audit_events e ON e.id = f.audit_event_id
        WHERE e.root_session_id IS NOT NULL
        GROUP BY e.root_session_id ORDER BY n DESC LIMIT 1`,
    )
    .get() as { id: string; n: number } | undefined;
  const sessionId = sessionRow?.id ?? '';

  const run: Record<ReadName, () => Promise<number>> = {
    groupedInSession: async () =>
      (await findings.listGroupedFindings({ sessionId })).totals.findings,
    flatInSession: async () => (await findings.listFindingInstances({ sessionId })).totals.findings,
    locationsInSession: async () =>
      (await findings.listFindingLocations({ sessionId })).totals.findings,
    groupedAll: async () => (await findings.listGroupedFindings({})).totals.findings,
  };

  const matched: Record<string, number> = {};
  const samples: Record<string, number[]> = {};
  for (const name of READS) {
    matched[name] = await run[name]();
    samples[name] = measure(run[name]);
  }
  return { corpus, matched, samples };
}

describe(`/findings read costs from ${SMALL_EVENTS.toLocaleString('en-US')} to ${LARGE_EVENTS.toLocaleString('en-US')} events`, () => {
  let smallStore: OwnedTempStore;
  let largeStore: OwnedTempStore;
  let small: Scale;
  let large: Scale;

  beforeAll(async () => {
    smallStore = createTempStore('aka-findings-scale-small-');
    largeStore = createTempStore('aka-findings-scale-large-');
    small = await seedAndMeasure(smallStore, SMALL_EVENTS);
    large = await seedAndMeasure(largeStore, LARGE_EVENTS);
  }, SEED_TIMEOUT_MS);

  afterAll(() => {
    smallStore.destroy();
    largeStore.destroy();
  });

  it('both corpora are at the stated scale, and ten times apart', () => {
    expect(small.corpus.events).toBe(SMALL_EVENTS);
    expect(large.corpus.events).toBe(LARGE_EVENTS);
    expect(large.corpus.findings / small.corpus.findings).toBeGreaterThan(5);
  });

  it('the two corpora carry the same number of resolutions, so only the store grew', () => {
    const a = small.corpus.resolutions;
    const b = large.corpus.resolutions;
    expect(a, 'small corpus seeded no resolutions').toBeGreaterThan(0);
    expect(b, 'large corpus seeded no resolutions').toBeGreaterThan(0);
    expect(
      Math.abs(a - b) / Math.max(a, b),
      `resolution counts diverged (${String(a)} vs ${String(b)}); the scoped ratios would then measure the resolution table, not the store`,
    ).toBeLessThan(RESOLUTION_TOLERANCE);
  });

  it('every read matched something at both sizes, so a ratio of 1 is not an empty scope', () => {
    for (const name of READS) {
      expect(
        small.matched[name],
        `${name} matched nothing at ${String(SMALL_EVENTS)}`,
      ).toBeGreaterThan(0);
      expect(
        large.matched[name],
        `${name} matched nothing at ${String(LARGE_EVENTS)}`,
      ).toBeGreaterThan(0);
    }
  });

  it('the session-scoped reads answer the same-sized question at both sizes', () => {
    // A session is EVENTS_PER_SESSION events at both sizes, so the scoped
    // answer must be of the same order — a large-side count many times the
    // small one would mean the scope leaked and the ratio below is measuring
    // the store after all.
    for (const name of FLAT_READS) {
      const a = small.matched[name] ?? 0;
      const b = large.matched[name] ?? 0;
      expect(b / a, `${name}: ${String(a)} matched at small, ${String(b)} at large`).toBeLessThan(
        FLATNESS_CEILING,
      );
    }
  });

  for (const name of FLAT_READS) {
    it(`${name} stays flat as the store grows`, () => {
      const smallest = fastest(small.samples[name] ?? []);
      const largest = fastest(large.samples[name] ?? []);
      const ratio = largest / smallest;
      expect(
        ratio,
        `${name} fastest-of-${String(SAMPLES)} was ${smallest.toFixed(3)} ms at ` +
          `${SMALL_EVENTS.toLocaleString('en-US')} events and ${largest.toFixed(3)} ms at ` +
          `${LARGE_EVENTS.toLocaleString('en-US')} — a ratio of ${ratio.toFixed(3)} across a 10x ` +
          `size step, where a cost linear in the store would read ~10`,
      ).toBeLessThan(FLATNESS_CEILING);
      expect(largest, `${name} at ${LARGE_EVENTS.toLocaleString('en-US')} events`).toBeLessThan(
        GROSS_REGRESSION_MS,
      );
    });
  }

  it('the unscoped grouped read grows with the store (the positive control)', () => {
    const smallest = fastest(small.samples.groupedAll ?? []);
    const largest = fastest(large.samples.groupedAll ?? []);
    const ratio = largest / smallest;
    expect(
      ratio,
      `groupedAll read ${smallest.toFixed(3)} ms at small and ${largest.toFixed(3)} ms at large — ` +
        `a ratio of ${ratio.toFixed(3)}. It counts every finding in the store and must grow; ` +
        `flat here means the harness is no longer measuring growth`,
    ).toBeGreaterThan(CONTROL_FLOOR);
  });
});
