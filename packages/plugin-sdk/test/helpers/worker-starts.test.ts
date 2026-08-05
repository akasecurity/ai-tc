/**
 * The counter the isolation suites assert through.
 *
 * It replaced an elapsed ceiling, so weakening it back would not fail any of
 * its callers — a count that always reads the expected number passes every one
 * of them. That is the failure this suite exists to catch, which is why each
 * case here drives the counter to a value the callers would never notice.
 *
 * What it does NOT cover is whether the seam fires once per real thread. That
 * needs a real scanner and lives in `../isolated-scan.test.ts`.
 */
import { describe, expect, it } from 'vitest';

import { countWorkerStarts } from './worker-starts.ts';

describe('countWorkerStarts', () => {
  it('counts nothing before a thread is reported', () => {
    const starts = countWorkerStarts();
    expect(starts.count()).toBe(0);
    expect(starts.ids()).toEqual([]);
  });

  it('counts each distinct thread once', () => {
    const starts = countWorkerStarts();
    starts.onWorkerStart(1);
    starts.onWorkerStart(2);
    starts.onWorkerStart(3);
    expect(starts.count()).toBe(3);
  });

  it('counts a repeated id once, so a double announcement cannot inflate it', () => {
    // Ids are unique per process and never reused, so a repeat is a seam that
    // announced one construction twice — never a second thread. Counting
    // notifications would report 3 threads here and quietly pass a case
    // expecting 3.
    const starts = countWorkerStarts();
    starts.onWorkerStart(7);
    starts.onWorkerStart(7);
    starts.onWorkerStart(7);
    expect(starts.count()).toBe(1);
  });

  it('keeps the raw log, duplicates and order included', () => {
    // The count is deduplicated; the log is not, so a wrong count can be read
    // rather than guessed at.
    const starts = countWorkerStarts();
    starts.onWorkerStart(4);
    starts.onWorkerStart(9);
    starts.onWorkerStart(4);
    expect(starts.ids()).toEqual([4, 9, 4]);
    expect(starts.count()).toBe(2);
  });

  it('hands back a copy of the log, so a caller cannot edit the count away', () => {
    const starts = countWorkerStarts();
    starts.onWorkerStart(5);
    starts.ids().push(6);
    expect(starts.count()).toBe(1);
    expect(starts.ids()).toEqual([5]);
  });

  it('gives each counter its own tally', () => {
    // Every case that asserts a count builds its own; sharing state between two
    // would make the second read the first's threads.
    const first = countWorkerStarts();
    const second = countWorkerStarts();
    first.onWorkerStart(1);
    expect(second.count()).toBe(0);
    expect(second.ids()).toEqual([]);
  });
});
