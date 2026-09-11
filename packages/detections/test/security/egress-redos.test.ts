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
// Two of the shapes below are crafted — a tag that never closes, a punctuation
// run that never ends. The rest are the ones worth reading twice: a minified
// bundle, the same bundle carrying one token, and manifests whose dependency
// count grows with their size. Nothing about those is an attack, and none of
// them looks like a ReDoS; each was work proportional to the FILE done once per
// HIT, which is the shape to recognise here.

// CPU time, in ms — the same instrument, and for the same reason, as the
// per-rule budget in redos.test.ts. The question is "does this pass do work
// proportional to the square of its input", which is a statement about WORK,
// while wall time measures ELAPSED. A thread the scheduler took the core away
// from accumulates wall time having executed nothing, so a wall-clock verdict
// here is satisfiable by a stall this code had no part in.
//
// `threadCpuUsage` rather than `cpuUsage`: the latter sums the whole PROCESS,
// V8's background GC and compiler threads included, which charges this pass
// with work it did not do and errs toward eating the budget's margin. Measured
// on the same calls, process-CPU reads ~2.3x thread-CPU here. It is the clock
// CLAUDE.md prescribes for the runtime work clock, for this reason.
const cpuMs = (): number => {
  const { user, system } = process.threadCpuUsage();
  return (user + system) / 1000;
};

function burned(work: () => unknown): number {
  const before = cpuMs();
  work();
  return cpuMs() - before;
}

// The FASTEST of a few passes on each side, which is the estimator this repo
// uses wherever a ratio has to survive a shared runner: noise only ever adds
// time, so the minimum is the one reading a loaded machine cannot inflate.
// Both sides use the same estimator over the same count — a stall-immune
// denominator against a noisy numerator is its own failure mode. That parity
// survives the growth block below, which times a WINDOW of repetitions rather
// than one pass: the estimator and the pass count are unchanged, and each side
// divides by its own repetition count before the two are compared.
const PASSES = 3;

function fastest(work: () => unknown): number {
  let best = Infinity;
  for (let i = 0; i < PASSES; i += 1) best = Math.min(best, burned(work));
  return best;
}

// Measured on an arm64 Mac, at the 1 MB cap: 2.5ms for the manifest shape,
// 3.3ms for the URL shape and 38.3ms for the minified bundle. What each case
// replaced costs MINUTES at that size — ~130s for the bundle, measured, and
// longer again for the manifest shape, which nobody has sat through. So the
// budget sits ~50x above the worst passing measurement and ~60x below the
// cheapest failure, which is what makes it a correctness assertion rather than
// a benchmark: no runner is slow enough to cross it, and no quadratic pass is
// fast enough to stay under it. Both margins are stated because only the
// smaller one bounds how far this can be tightened.
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

// The same bundle carrying ONE masked value in its first unit. Assembled from
// fragments rather than written whole: a credential-shaped literal in a public
// repository is exactly what this product exists to find, and the scanner that
// fronts this tree rewrites one before it reaches disk.
const MASKED_LEAD = `const h = "${['Author', 'ization'].join('')}: ${['Bea', 'rer'].join('')} ${[
  'abcdefghij',
  'klmnopqrst',
  'uvwxyz0123',
  '45',
].join('')}"; `;
const maskedBundle = (bytes: number): string => MASKED_LEAD + minifiedBundle(bytes);

// A package.json whose dependency count grows with its size — which is what
// every manifest looks like. Both shapes are ordinary: `pretty` is what a human
// commits, `minified` is what tooling writes.
function packageJson(bytes: number, minified: boolean): string {
  const dependencies: Record<string, string> = {};
  // ~48 bytes per entry pretty, ~42 minified; overshooting is harmless because
  // the assertion below pins the size that actually reaches the extractor.
  const count = Math.floor(bytes / (minified ? 42 : 48));
  for (let i = 0; i < count; i += 1) {
    dependencies[`@scope/package-name-number-${String(i)}`] = '^1.2.3';
  }
  const manifest = { name: 'x', version: '1.0.0', dependencies };
  return minified ? JSON.stringify(manifest) : JSON.stringify(manifest, null, 2);
}

// The same names in two sections, so the ORDER decides whether each key's first
// occurrence sits before or after the section being read. Both orderings are
// ordinary: `peerDependencies` above `dependencies` is what a hand-edited
// manifest looks like, and `require-dev` above `require` is the composer.json
// equivalent.
function packageJsonSections(bytes: number, peerFirst: boolean): string {
  const dependencies: Record<string, string> = {};
  const count = Math.floor(bytes / 96);
  for (let i = 0; i < count; i += 1) {
    dependencies[`@scope/package-name-number-${String(i)}`] = '^1.2.3';
  }
  const manifest = peerFirst
    ? { name: 'x', peerDependencies: dependencies, dependencies }
    : { name: 'x', dependencies, peerDependencies: dependencies };
  return JSON.stringify(manifest, null, 2);
}

// A pom.xml on ONE line. The JSON manifests above reach `hitAtQuotedKey`; this
// shape reaches the `eachLine` extractors, which take their snippet from the
// line they are on — and a manifest written on one line has exactly one.
function minifiedPom(bytes: number): string {
  const entry = (i: number): string =>
    `<dependency><groupId>com.example.group${String(i)}</groupId>` +
    `<artifactId>a${String(i)}</artifactId></dependency>`;
  let body = '';
  for (let i = 0; body.length < bytes; i += 1) body += entry(i);
  return `<project><dependencies>${body}</dependencies></project>`;
}

describe('egress extraction is bounded on a 1 MB file', () => {
  // The premise `cpuMs` rests on — and it is NOT the one `process.cpuUsage()`
  // needed. A thread clock is already per thread, so a threads pool would not
  // put another file's own work on this measurement. What it would put here is
  // that file's GARBAGE: a pool shares one heap, so V8 collecting another
  // file's allocations runs on whichever thread allocates next, and the budget
  // below would absorb it. Vitest's default `forks` pool gives each file its
  // own process and heap; no package in this workspace sets `pool` today.
  it('runs in its own process, so no other test file shares this heap', () => {
    expect(
      isMainThread,
      'this suite is running as a worker thread, so it now shares a heap with every test file in ' +
        'the pool and GC for their allocations can land inside these measurements. Restore ' +
        'per-process isolation rather than widening the budget.',
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

  it('takes a snippet per hit from a 1 MB bundle that carries a masked value', () => {
    // The case above has nothing to mask, so its per-line redaction leaves the
    // line the same length and the anchor never has to be mapped at all. One
    // masked value anywhere on the line turns that mapping on for EVERY hit —
    // and a bundle with a token in it is the file this product is pointed at on
    // purpose, so it is the case that matters most.
    const text = maskedBundle(MB);
    const ms = burned(() => extractEgress(text));
    expect(
      ms,
      `extractEgress burned ${ms.toFixed(1)}ms of CPU on a 1 MB minified bundle carrying one ` +
        `masked value (budget ${String(EXTRACTION_BUDGET_MS)}ms). The anchor is being mapped by ` +
        `re-redacting the prefix per hit again — build the per-pass edit lists once per line.`,
    ).toBeLessThan(EXTRACTION_BUDGET_MS);
  });

  it.each([
    ['pretty-printed', false],
    ['minified', true],
  ])('resolves every dependency of a 1 MB %s package.json', (_label, minified) => {
    const text = packageJson(MB, minified);
    const hits = extractManifestSdks(text, 'package.json');
    // Positive controls: a manifest the extractor found nothing in costs
    // nothing, and would satisfy the budget while proving the opposite.
    expect(text.length).toBeGreaterThan(MB / 2);
    expect(hits.length).toBeGreaterThan(10_000);

    const ms = burned(() => extractManifestSdks(text, 'package.json'));
    expect(
      ms,
      `extractManifestSdks burned ${ms.toFixed(1)}ms of CPU resolving ${String(hits.length)} ` +
        `dependencies in a 1 MB manifest (budget ${String(EXTRACTION_BUDGET_MS)}ms). Something ` +
        `on that path is walking the whole file per HIT again — the line number, the snippet, ` +
        `or the search for the quoted key.`,
    ).toBeLessThan(EXTRACTION_BUDGET_MS);
  });

  it('costs the same however a manifest orders its sections', () => {
    // A BUDGET would not catch this. The quoted-key index answered only each
    // token's FIRST offset, so every name whose first occurrence sat before the
    // section being read fell back to the per-hit `indexOf` — measured at 350ms
    // for a 1 MB manifest, comfortably inside the 2,000ms budget while being
    // quadratic (7.5 / 27.4 / 99.6 / 350.0 ms across 128KB to 1MB). What
    // separates the two is that reordering the sections must not change the
    // cost at all, so the ratio is the assertion.
    const depsFirst = packageJsonSections(MB, false);
    const peerFirst = packageJsonSections(MB, true);
    // Positive controls: the same hits either way, and enough of them that the
    // per-hit path is what is being measured.
    expect(extractManifestSdks(peerFirst, 'package.json').length).toBe(
      extractManifestSdks(depsFirst, 'package.json').length,
    );
    expect(extractManifestSdks(depsFirst, 'package.json').length).toBeGreaterThan(5_000);

    const ordered = fastest(() => extractManifestSdks(depsFirst, 'package.json'));
    const reversed = fastest(() => extractManifestSdks(peerFirst, 'package.json'));
    expect(
      reversed / Math.max(ordered, 1),
      `the same 1 MB manifest cost ${ordered.toFixed(1)}ms with dependencies first and ` +
        `${reversed.toFixed(1)}ms with peerDependencies first. Section order is deciding the ` +
        `cost, which means a key whose first occurrence precedes its section is back on the ` +
        `per-hit scan — index every offset per token, not just the first.`,
    ).toBeLessThan(3);
  });

  it('resolves every dependency of a 1 MB single-line pom.xml', () => {
    const text = minifiedPom(MB);
    const hits = extractManifestSdks(text, 'pom.xml');
    // Positive controls: a manifest the extractor found nothing in costs
    // nothing, and would satisfy the budget while proving the opposite.
    expect(text.length).toBeGreaterThan(MB / 2);
    expect(hits.length).toBeGreaterThan(5_000);

    const ms = burned(() => extractManifestSdks(text, 'pom.xml'));
    expect(
      ms,
      `extractManifestSdks burned ${ms.toFixed(1)}ms of CPU resolving ${String(hits.length)} ` +
        `dependencies in a 1 MB single-line pom (budget ${String(EXTRACTION_BUDGET_MS)}ms). The ` +
        `line's snippet is being redacted per HIT again rather than once per line.`,
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

    // And the masked variant, which reaches the anchor mapping the plain one
    // never touches: same urls, and every snippet still 200 characters of the
    // redacted line rather than a window mapped off the end of it.
    const masked = extractEgress(maskedBundle(200_000));
    expect(masked.map((h) => h.url)).toEqual(fromOne.map((h) => h.url));
    expect(masked.every((h) => h.snippet.length <= 200)).toBe(true);
    // The window still lands on the surrounding evidence rather than off the
    // end of it. Asserted on the unit's PROSE, not on its host: a substring
    // test against a hostname is what an incomplete-URL-sanitization check
    // looks like, and this file should not be teaching that shape.
    expect(masked.some((h) => h.snippet.includes('for details'))).toBe(true);
  });
});

describe('the inputs above are adversarial for what they replaced', () => {
  // Positive controls, without which a case fed a harmless string would satisfy
  // its budget for ever and report the bound as held.
  //
  // Each measures the SAME replaced shape at two input sizes and asserts it
  // GROWS super-linearly: doubling the input doubles a linear pass and
  // quadruples a quadratic one. That is the property a control here is actually
  // claiming — "this input still makes the old shape blow up" — and it cancels
  // the machine outright, because both readings come from one run on one
  // runner.
  //
  // These compared the replaced shape against the CURRENT extraction before,
  // and that shape was wrong twice on the same leg: the quotient depends on how
  // expensive the modern code happens to be on that machine, which has nothing
  // to do with the claim. It read 12.7x and 15.7x on a Windows runner against
  // the 20x demanded, while passing locally. Shrinking the inputs to a
  // thirty-second (worth doing on its own terms — 4.7s of by-design quadratic
  // work in a package whose testTimeout is 20s) narrowed the same margin
  // further, because a quadratic side shrinks 4x where a linear one shrinks 2x.
  // Do not put an absolute or cross-implementation comparison back.
  const SMALL = MB / 128;
  const LARGE = SMALL * 2;

  // Between linear's 2 and quadratic's 4.
  const SUPERLINEAR = 3;

  // Both readings are divided into each other, so everything the two share
  // cancels and a uniformly slower machine moves the quotient not at all. What
  // does NOT cancel is the CLOCK. A delta between two quantized readings
  // carries up to a tick of error whichever way it falls, and at these input
  // sizes a tick can be most of the measurement: POSIX reports microseconds
  // (0.001ms, measured), while Windows credits a whole scheduler tick — ~15.6ms
  // — to whichever thread was running at the timer interrupt.
  //
  // That is not hypothetical, and it is not inferred. A Windows leg read
  // `taking a snippet per hit` at 15.0ms and 31.0ms — a ratio of 2.07 against
  // the 3 demanded, reported out as LINEAR — for a shape that measures 7.9ms
  // and 31.2ms on an arm64 Mac and stays quadratic (3.88 / 3.98 / 4.00) across
  // three further doublings. The runner's own clock produced those two numbers:
  // its smallest non-zero `threadCpuUsage` delta measures 16.0000ms, which the
  // `Runner facts` step in ci.yml reports, so 15.0 and 31.0 are one and two
  // ticks of it and a 7.9ms quantity has nowhere to land but a whole tick.
  //
  // The second case was owed the same fix whatever that leg had done.
  // `counting each hit's line from zero` measures 0.99ms here, where the old
  // floor of 1ms turned its quotient into `large > 3ms` — an absolute threshold
  // wearing a ratio's clothes, which is the one shape this file argues against
  // everywhere else.
  //
  // So each side is measured over as many REPETITIONS as it takes to fill a
  // window the clock can resolve, then divided by its own repetition count.
  // Repetitions rather than a larger input, because these are the quadratic
  // shapes: doubling the input to buy a readable window costs four times the
  // work where doubling the repetitions costs two. And each side is sized
  // independently, so the expensive side fills the same window with a quarter
  // of the passes rather than overshooting it fourfold.
  //
  // The cost is therefore bounded by the WINDOW rather than by the machine — a
  // slower runner fills the same window with fewer passes — so this does not
  // grow the wall clock on the leg that prompted it.

  /**
   * The smallest non-zero interval this thread's CPU clock reports.
   *
   * The probe's busy loop GROWS until a delta appears: one sized for a
   * microsecond clock reads zero on a coarse clock for ever, and reporting zero
   * would hand the caller a window of no width at all.
   */
  function clockResolutionMs(): number {
    for (let work = 1_000; work <= 134_217_728; work *= 8) {
      let best = Infinity;
      let seen = 0;
      for (let attempt = 0; attempt < 32 && seen < 8; attempt += 1) {
        const before = cpuMs();
        let sink = 0;
        for (let i = 0; i < work; i += 1) sink += i;
        const delta = cpuMs() - before;
        // `sink` is read so the loop cannot be optimized away outright. Were it
        // removed, every delta would read zero, the work would grow to the cap,
        // and this would report an unusable clock rather than a fast one.
        if (delta > 0 && sink >= 0) {
          best = Math.min(best, delta);
          seen += 1;
        }
      }
      if (best !== Infinity) return best;
    }
    return Infinity;
  }

  const CLOCK_RESOLUTION_MS = clockResolutionMs();

  // How many resolutions wide one timed window has to be. Each side then
  // carries at most 1/16 of relative error and the quotient at most ~1/8, which
  // leaves a genuinely quadratic shape reading 3.5 or better against the 3
  // demanded, and a genuinely linear one 2.25 or worse.
  const RESOLUTION_MARGIN = 16;

  // The absolute floor beneath the clock-derived one. On a microsecond clock
  // the margin above lands at 16us, and a window that short measures whatever
  // the collector happened to do inside it rather than the shape.
  const MIN_WINDOW_MS = 5;

  const WINDOW_MS = Math.max(MIN_WINDOW_MS, CLOCK_RESOLUTION_MS * RESOLUTION_MARGIN);

  /** How many passes of `work` fill one window, sized from a measurement. */
  function repetitionsFilling(work: () => unknown): number {
    let reps = 1;
    for (let attempt = 0; attempt < 32; attempt += 1) {
      const ms = burned(() => {
        for (let i = 0; i < reps; i += 1) work();
      });
      if (ms >= WINDOW_MS) return reps;
      // Aim at the window from what was just measured, with a little overshoot.
      // A reading the clock rounded to zero carries no scale to aim with, so
      // step blind instead of dividing by it.
      const aimed = ms > 0 ? Math.ceil(reps * (WINDOW_MS / ms) * 1.25) : reps * 8;
      reps = Math.max(reps + 1, aimed);
    }
    throw new Error(
      `could not fill a ${WINDOW_MS.toFixed(3)}ms window in 32 attempts, at a measured clock ` +
        `resolution of ${CLOCK_RESOLUTION_MS.toFixed(4)}ms. The growth measurement below cannot ` +
        `be trusted on this clock, so it is refused rather than reported.`,
    );
  }

  function growth(shape: (bytes: number) => () => unknown): {
    small: number;
    large: number;
    ratio: number;
    window: string;
  } {
    const smallWork = shape(SMALL);
    const largeWork = shape(LARGE);
    const smallReps = repetitionsFilling(smallWork);
    const largeReps = repetitionsFilling(largeWork);
    const over = (work: () => unknown, reps: number) => (): void => {
      for (let i = 0; i < reps; i += 1) work();
    };
    const small = fastest(over(smallWork, smallReps)) / smallReps;
    const large = fastest(over(largeWork, largeReps)) / largeReps;
    if (small === 0) {
      throw new Error(
        `the small side measured 0ms over ${String(smallReps)} passes, after a window sized to ` +
          `${WINDOW_MS.toFixed(3)}ms. The clock moved under the measurement; refusing to divide ` +
          `by it rather than reporting the quotient that produces.`,
      );
    }
    return {
      small,
      large,
      ratio: large / small,
      window:
        `${WINDOW_MS.toFixed(3)}ms windows at a measured clock resolution of ` +
        `${CLOCK_RESOLUTION_MS.toFixed(4)}ms, filled by ${String(smallReps)} and ` +
        `${String(largeReps)} passes`,
    };
  }

  function expectSuperlinear(
    label: string,
    measured: { small: number; large: number; ratio: number; window: string },
  ): void {
    expect(
      measured.ratio,
      `${label} cost ${measured.small.toFixed(3)}ms and ${measured.large.toFixed(3)}ms per pass ` +
        `at one and two units of input — a ratio of ${measured.ratio.toFixed(2)}, i.e. LINEAR. ` +
        `This input no longer makes that shape blow up, so the budget case it backs proves ` +
        `nothing. Rebuild the hostile shape. Measured over ${measured.window}, so the clock is ` +
        `not what produced this.`,
    ).toBeGreaterThan(SUPERLINEAR);
  }

  it('the manifest line is quadratic under the pattern it replaced', () => {
    expectSuperlinear(
      'the replaced tag pattern',
      growth((bytes) => {
        const text = hostileManifest(bytes);
        return () => [...text.matchAll(REPLACED_XML_TAG)];
      }),
    );
  });

  it('the URL candidate is quadratic under the pattern it replaced', () => {
    expectSuperlinear(
      'the replaced punctuation pattern',
      growth((bytes) => {
        const text = hostileUrl(bytes);
        return () => text.replace(REPLACED_TRAILING_PUNCTUATION, '');
      }),
    );
  });

  it('the manifest is quadratic when each hit walks the file for its line number', () => {
    // The replaced shape, frozen: a line number counted from offset zero, once
    // per dependency. `lineNumberAt` is gone from the source, so this copy is a
    // historical artifact whose only job is to show the input still makes it
    // quadratic.
    expectSuperlinear(
      "counting each hit's line from zero",
      growth((bytes) => {
        const text = packageJson(bytes, false);
        const keys = Object.keys(
          (JSON.parse(text) as { dependencies: Record<string, string> }).dependencies,
        );
        return () => {
          let total = 0;
          for (const key of keys) {
            const index = text.indexOf(`"${key}"`);
            let line = 1;
            for (let i = 0; i < index; i += 1) if (text[i] === '\n') line += 1;
            total += line;
          }
          return total;
        };
      }),
    );
  });

  it('the bundle is quadratic when its snippet is taken per hit', () => {
    // This control needs no frozen copy. `redactSnippet` is the PUBLIC
    // single-line entry point and still does the per-line work on every call —
    // correct for one call, and exactly what extractEgress must not do per hit.
    // So it measures the live shape the memoization avoids rather than a copy
    // of it, and it goes stale only if that entry point itself changes.
    expectSuperlinear(
      'taking a snippet per hit',
      growth((bytes) => {
        const line = minifiedBundle(bytes);
        const hits = Math.floor(line.length / MINIFIED_UNIT.length);
        return () => {
          let total = 0;
          for (let i = 0; i < hits; i += 1) {
            total += redactSnippet(line, i * MINIFIED_UNIT.length).length;
          }
          return total;
        };
      }),
    );
  });
});
