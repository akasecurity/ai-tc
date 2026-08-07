/**
 * The corpus generator's DENSITY knob.
 *
 * `spacingMs` is the milliseconds between consecutive generated events, and for
 * any windowed read it is as load-bearing as the event count — a fact that is
 * easy to miss because the event count is the number everyone quotes. At the
 * 1 s default a million events span 11.6 days, so a `30d` window contains the
 * entire store and a windowed aggregation costs exactly what an unwindowed one
 * does. That is not a faster or slower measurement, it is a measurement of a
 * different thing: no real install puts a million events into eleven days.
 *
 * So the knob exists, and these cases pin the two properties a caller relies
 * on — that it actually moves the timestamps, and that `endsAt` (the clock a
 * windowed read must be driven with) moves with it. A generator whose `endsAt`
 * did not track its own spacing would hand every windowed read a cutoff past
 * the whole corpus, and the read would match nothing while still returning a
 * plan and a plausible number.
 */
import { describe, expect, it } from 'vitest';

import { CORPUS_EPOCH_MS, corpusConnection, seedCaptureCorpus } from '../helpers/corpus.ts';
import { createTempStore } from '../helpers/temp-store.ts';

const EVENTS = 200;
const DAY_MS = 86_400_000;

/** Earliest and latest `started_at` among the capture rows. */
function span(dataDirDb: ReturnType<typeof corpusConnection>): { min: number; max: number } {
  return dataDirDb
    .prepare(`SELECT MIN(started_at) AS min, MAX(started_at) AS max FROM audit_events`)
    .get() as { min: number; max: number };
}

describe('generated corpus density', () => {
  it('spreads the same event count across the span spacingMs asks for', () => {
    const store = createTempStore('aka-density-');
    try {
      const db = store.open();
      const corpus = seedCaptureCorpus(db, { events: EVENTS, sessions: 5, spacingMs: DAY_MS });

      // The knob is reported back, so a caller can put it in a result table
      // rather than restating what it passed.
      expect(corpus.spacingMs).toBe(DAY_MS);

      const { min, max } = span(corpusConnection(db));
      expect(min).toBe(CORPUS_EPOCH_MS);
      // 200 events one day apart: the last one sits 199 days after the first.
      expect(max - min).toBe((EVENTS - 1) * DAY_MS);

      // `endsAt` is just past the last event, in the SAME units — this is the
      // value a windowed read is driven with, so it has to track the spacing
      // rather than the default.
      expect(corpus.endsAt).toBe(CORPUS_EPOCH_MS + EVENTS * DAY_MS);
      expect(corpus.endsAt).toBeGreaterThan(max);
    } finally {
      store.destroy();
    }
  });

  it('defaults to one second, and the default is what the constant says', () => {
    const store = createTempStore('aka-density-default-');
    try {
      const db = store.open();
      // The positive control for the case above: without this, a `spacingMs`
      // that was silently ignored would still satisfy every assertion there if
      // the default happened to equal the value passed.
      const corpus = seedCaptureCorpus(db, { events: EVENTS, sessions: 5 });
      expect(corpus.spacingMs).toBe(1_000);

      const { min, max } = span(corpusConnection(db));
      expect(max - min).toBe((EVENTS - 1) * 1_000);
      expect(max - min).not.toBe((EVENTS - 1) * DAY_MS);
    } finally {
      store.destroy();
    }
  });

  it('refuses a spacing that is not a positive integer', () => {
    const store = createTempStore('aka-density-bad-');
    try {
      const db = store.open();
      // Same reasoning as `findingRate`: a bad value here does not fail, it
      // silently produces a corpus of a shape nobody asked for.
      expect(() => seedCaptureCorpus(db, { events: 10, spacingMs: 0 })).toThrow(
        /spacingMs must be a positive integer/,
      );
      expect(() => seedCaptureCorpus(db, { events: 10, spacingMs: 1.5 })).toThrow(
        /spacingMs must be a positive integer/,
      );
      expect(() => seedCaptureCorpus(db, { events: 10, spacingMs: Number.NaN })).toThrow(
        /spacingMs must be a positive integer/,
      );
    } finally {
      store.destroy();
    }
  });
});
