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
// denominator against a noisy numerator is its own failure mode.
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

  // Between linear's 2 and quadratic's 4. The floor keeps a sub-tick small side
  // from making the quotient meaningless — without it a fast machine that
  // measures 0 at SMALL turns any large reading into a pass.
  const SUPERLINEAR = 3;
  const FLOOR_MS = 1;

  function growth(shape: (bytes: number) => () => unknown): {
    small: number;
    large: number;
    ratio: number;
  } {
    const small = fastest(shape(SMALL));
    const large = fastest(shape(LARGE));
    return { small, large, ratio: large / Math.max(small, FLOOR_MS) };
  }

  function expectSuperlinear(
    label: string,
    measured: { small: number; large: number; ratio: number },
  ): void {
    expect(
      measured.ratio,
      `${label} cost ${measured.small.toFixed(1)}ms and ${measured.large.toFixed(1)}ms at one ` +
        `and two units of input — a ratio of ${measured.ratio.toFixed(2)}, i.e. LINEAR. This ` +
        `input no longer makes that shape blow up, so the budget case it backs proves nothing. ` +
        `Rebuild the hostile shape.`,
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
