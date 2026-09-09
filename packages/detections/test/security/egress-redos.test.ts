import { isMainThread } from 'node:worker_threads';

import { describe, expect, it } from 'vitest';

import { extractEgress, redactSnippet } from '../../src/egress/extract.ts';
import { extractManifestSdks } from '../../src/egress/manifests.ts';

// Egress extraction is the OTHER unbounded pass over file content, and it is not
// the one the isolated-scan worker covers. `scanPathIntoStore` runs
// `extractFileEgress` on the CALLING thread, before and independent of the
// guarded scan, so nothing can interrupt it — and its two callers are `aka scan`
// and the dashboard's folder-scan Server Action, which has no harness timeout at
// all. A pass that is quadratic in file length is therefore a denial of service
// reachable from any repository somebody points the scanner at.
//
// The walker caps a file at 1 MB (MAX_BYTES in @akasecurity/local-ops), so 1 MB
// is the real ceiling on what reaches here, and it is what these cases feed.
//
// Three shapes, and the third is the one worth reading twice: the first two are
// crafted, and the third is an ordinary minified bundle.

// CPU time, in ms — the same instrument, and for the same reason, as the
// per-rule budget in redos.test.ts. The question is "does this pass do work
// proportional to the square of its input", which is a statement about WORK,
// while wall time measures ELAPSED. A thread the scheduler took the core away
// from accumulates wall time having executed nothing, so a wall-clock verdict
// here is satisfiable by a stall this code had no part in.
const cpuMs = (): number => {
  const { user, system } = process.cpuUsage();
  return (user + system) / 1000;
};

function burned(work: () => unknown): number {
  const before = cpuMs();
  work();
  return cpuMs() - before;
}

// Measured on an arm64 Mac, at the 1 MB cap: 2.5ms for the manifest shape,
// 3.3ms for the URL shape and 38.3ms for the minified bundle. The quadratic
// behaviour each case replaced costs, at the same size, minutes — roughly 11 for
// the manifest shape and 2 for the bundle. So this budget sits ~50x above the
// worst passing measurement and ~3,000x below the cheapest failure, which is
// what makes it a correctness assertion rather than a benchmark: no runner is
// slow enough to cross it and no quadratic pass is fast enough to stay under it.
const EXTRACTION_BUDGET_MS = 2_000;

const MB = 1_000_000;

// The patterns these cases exist to keep retired. They are frozen copies, not
// live ones — nothing in `src/` spells either of them any more — and their only
// job is to prove the inputs below really are adversarial. Without them a case
// fed a harmless input would pass for ever.
const REPLACED_XML_TAG = /<(\/?)([A-Za-z][\w.-]*)([^<>]*)>/g;
const REPLACED_TRAILING_PUNCTUATION = /[.,;:'"]+$/;

// `<a` then a run of word characters and no closing bracket. The name group and
// the attribute group share an alphabet, so every split point of the run is
// retried against the rest of the line.
const hostileManifest = (bytes: number): string => `<a${'z'.repeat(bytes - 2)}`;

// A URL whose trailing punctuation run does not reach the end of the string, so
// the anchored strip fails after consuming the whole run, at every start.
const hostileUrl = (bytes: number): string => `https://x.co/${'.'.repeat(bytes - 14)}a`;

// An ordinary minified bundle: one very long line carrying many URLs. Nothing
// about it is crafted, which is what makes it the important case — the snippet
// for each hit is taken from its line, and there is only ever one line.
const MINIFIED_UNIT = 'see https://example.com/a for details. ';
const minifiedBundle = (bytes: number): string =>
  MINIFIED_UNIT.repeat(Math.ceil(bytes / MINIFIED_UNIT.length));

describe('egress extraction is bounded on a 1 MB file', () => {
  // The premise `cpuMs` rests on. `process.cpuUsage()` sums the whole process,
  // so charging CPU to one extraction is only a measurement of that extraction
  // while this file has the process to itself. Vitest's default `forks` pool
  // gives each file its own child process; `pool: 'threads'` would make this
  // read false and every budget here start measuring other suites too.
  it('runs as its own process, which is what makes a process-wide CPU clock a per-case measurement', () => {
    expect(
      isMainThread,
      'this suite is running as a worker thread, so process.cpuUsage() now sums every test file ' +
        'sharing this process. Restore per-process isolation rather than widening the budget.',
    ).toBe(true);
  });

  it('parses a manifest line that never closes its tag', () => {
    const text = hostileManifest(MB);
    const ms = burned(() => extractManifestSdks(text, 'pom.xml'));
    expect(
      ms,
      `extractManifestSdks burned ${ms.toFixed(1)}ms of CPU on a 1 MB manifest line ` +
        `(budget ${String(EXTRACTION_BUDGET_MS)}ms). The tag pattern is quadratic again: keep the ` +
        `attribute group from starting with a character the name group could also take.`,
    ).toBeLessThan(EXTRACTION_BUDGET_MS);
  });

  it('strips trailing punctuation from a 1 MB URL candidate', () => {
    const text = hostileUrl(MB);
    const ms = burned(() => extractEgress(text));
    expect(
      ms,
      `extractEgress burned ${ms.toFixed(1)}ms of CPU on a 1 MB URL candidate ` +
        `(budget ${String(EXTRACTION_BUDGET_MS)}ms). Trailing punctuation is being stripped with an ` +
        `anchored pattern again rather than scanned from the end.`,
    ).toBeLessThan(EXTRACTION_BUDGET_MS);
  });

  it('takes a snippet per hit from a 1 MB single-line bundle', () => {
    const text = minifiedBundle(MB);
    const ms = burned(() => extractEgress(text));
    expect(
      ms,
      `extractEgress burned ${ms.toFixed(1)}ms of CPU on a 1 MB minified bundle ` +
        `(budget ${String(EXTRACTION_BUDGET_MS)}ms). The per-line redaction is being recomputed per HIT ` +
        `again — memoize it by line index the way lineTextOf is.`,
    ).toBeLessThan(EXTRACTION_BUDGET_MS);
  });

  it('extracts the same hits from that bundle however its lines are broken', () => {
    // The bound above is worth nothing if the fast path became fast by
    // extracting less. Same bytes, same hits, one line against many.
    const oneLine = minifiedBundle(200_000);
    const manyLines = `${MINIFIED_UNIT.trimEnd()}\n`.repeat(
      Math.ceil(200_000 / MINIFIED_UNIT.length),
    );
    const fromOne = extractEgress(oneLine);
    const fromMany = extractEgress(manyLines);
    expect(fromOne.length).toBe(fromMany.length);
    expect(fromOne.length).toBeGreaterThan(1_000);
    expect(fromOne.map((h) => h.url)).toEqual(fromMany.map((h) => h.url));
  });
});

describe('the inputs above are adversarial for what they replaced', () => {
  // Positive controls, without which a case fed a harmless string would satisfy
  // its budget for ever and report the bound as held.
  //
  // Each is a RATIO of two measurements taken on the same machine, over the same
  // input, in the same run — the replaced shape against the current one — rather
  // than an elapsed lower bound. A lower bound is a statement about the runner:
  // it has to be small enough for the slowest leg, and every machine that gets
  // faster walks the real margin down toward it silently. A ratio cancels the
  // machine, which is what lets the margin below be enormous and stay meaningful.
  //
  // The inputs are 16x SMALLER than the cases above, because the replaced shapes
  // are quadratic and this suite has to finish.
  const SMALL = MB / 16;

  // The floor keeps the comparison honest when the current shape measures below
  // the clock's granularity: without it, `0 * FACTOR` is a threshold anything
  // clears, and the control would pass on a machine where nothing was measured.
  const FACTOR = 20;
  const FLOOR_MS = 1;

  function ratio(replaced: () => unknown, current: () => unknown): { old: number; now: number } {
    return { old: burned(replaced), now: burned(current) };
  }

  it('the manifest line is quadratic under the pattern it replaced', () => {
    const text = hostileManifest(SMALL);
    const { old, now } = ratio(
      () => [...text.matchAll(REPLACED_XML_TAG)],
      () => extractManifestSdks(text, 'pom.xml'),
    );
    expect(
      old,
      `the replaced tag pattern cost ${old.toFixed(1)}ms against the current ${now.toFixed(1)}ms ` +
        'on the same input, so this input no longer makes it backtrack and the budget case ' +
        'above proves nothing. Rebuild the hostile shape.',
    ).toBeGreaterThan(Math.max(now, FLOOR_MS) * FACTOR);
  });

  it('the URL candidate is quadratic under the pattern it replaced', () => {
    const text = hostileUrl(SMALL);
    const { old, now } = ratio(
      () => text.replace(REPLACED_TRAILING_PUNCTUATION, ''),
      () => extractEgress(text),
    );
    expect(
      old,
      `the replaced punctuation pattern cost ${old.toFixed(1)}ms against the current ` +
        `${now.toFixed(1)}ms for the whole extraction, so this input no longer makes it ` +
        'backtrack. Rebuild the hostile shape.',
    ).toBeGreaterThan(Math.max(now, FLOOR_MS) * FACTOR);
  });

  it('the bundle is quadratic when its snippet is taken per hit', () => {
    // This control needs no frozen copy. `redactSnippet` is the PUBLIC
    // single-line entry point and still does the per-line work on every call —
    // correct for one call, and exactly what extractEgress must not do per hit.
    // So it measures the live shape the memoization avoids rather than a copy
    // of it, and it goes stale only if that entry point itself changes.
    const line = minifiedBundle(SMALL);
    const hits = Math.floor(line.length / MINIFIED_UNIT.length);
    const { old, now } = ratio(
      () => {
        let total = 0;
        for (let i = 0; i < hits; i += 1) {
          total += redactSnippet(line, i * MINIFIED_UNIT.length).length;
        }
        return total;
      },
      () => extractEgress(line),
    );
    expect(
      old,
      `taking a snippet per hit cost ${old.toFixed(1)}ms against ${now.toFixed(1)}ms for the ` +
        'whole extraction of the same line, so the bundle case above proves nothing about the ' +
        'memoization.',
    ).toBeGreaterThan(Math.max(now, FLOOR_MS) * FACTOR);
  });
});
