import { describe, expect, it } from 'vitest';

import {
  type CoverageIndex,
  diffCoverage,
  evaluateGate,
  formatLineRanges,
  formatReport,
  indexIstanbulReport,
  type IstanbulFileCoverage,
  mergeCoverageIndexes,
  parseNumericFlag,
  parseUnifiedDiff,
} from '../src/lib.ts';

/** A `coverage-final.json` entry: one statement per line, with the given hits. */
const fileCoverage = (path: string, hitsByLine: Record<number, number>): IstanbulFileCoverage => {
  const statementMap: Record<string, { start: { line: number } }> = {};
  const s: Record<string, number> = {};
  for (const [index, [line, hits]] of Object.entries(hitsByLine).entries()) {
    statementMap[String(index)] = { start: { line: Number(line) } };
    s[String(index)] = hits;
  }
  return { path, statementMap, s };
};

const identity = (p: string) => p;

const indexOf = (files: Record<string, Record<number, number>>): CoverageIndex =>
  indexIstanbulReport(
    Object.fromEntries(Object.entries(files).map(([p, h]) => [p, fileCoverage(p, h)])),
    identity,
  );

describe('parseUnifiedDiff', () => {
  it('attributes added lines to the new-side path at the hunk offset', () => {
    const diff = [
      'diff --git a/src/a.ts b/src/a.ts',
      '--- a/src/a.ts',
      '+++ b/src/a.ts',
      '@@ -10,0 +11,2 @@',
      '+const x = 1;',
      '+const y = 2;',
      '@@ -20,0 +30,1 @@',
      '+const z = 3;',
    ].join('\n');

    expect(parseUnifiedDiff(diff)).toEqual(new Map([['src/a.ts', new Set([11, 12, 30])]]));
  });

  it('ignores removed lines and the ---/+++ headers themselves', () => {
    // The header lines begin with '+++' and '---'. Counted as content they
    // would add a phantom line to every file in every diff — and because they
    // sit before the first hunk header, that phantom lands at whatever offset
    // the previous file left behind.
    const diff = [
      '--- a/src/a.ts',
      '+++ b/src/a.ts',
      '@@ -1,2 +1,1 @@',
      '-const gone = 1;',
      '-const alsoGone = 2;',
      '+const kept = 1;',
    ].join('\n');

    expect(parseUnifiedDiff(diff)).toEqual(new Map([['src/a.ts', new Set([1])]]));
  });

  it('attributes nothing to a deleted file', () => {
    const diff = ['--- a/src/gone.ts', '+++ /dev/null', '@@ -1,2 +0,0 @@', '-a', '-b'].join('\n');

    expect(parseUnifiedDiff(diff)).toEqual(new Map());
  });

  it('reads a hunk header with no explicit count as one line', () => {
    // `@@ -0,0 +5 @@` is git's spelling for a single added line. Read as zero
    // it silently drops that line from the denominator AND the numerator.
    const diff = ['--- a/src/a.ts', '+++ b/src/a.ts', '@@ -4,0 +5 @@', '+const one = 1;'].join(
      '\n',
    );

    expect(parseUnifiedDiff(diff)).toEqual(new Map([['src/a.ts', new Set([5])]]));
  });

  it('treats a `+++ ` line INSIDE a hunk as content, not as a file header', () => {
    // An added line whose content begins with `++ ` is emitted as `+++ `, which
    // is byte-identical to a file header. Read as one, the real file drops out
    // of the diff entirely and a phantom path is invented from the rest of the
    // line — so the change is measured against the wrong denominator and scores
    // higher than it should. `remaining` is what separates the two.
    const diff = [
      'diff --git a/doc.md b/doc.md',
      '--- a/doc.md',
      '+++ b/doc.md',
      '@@ -0,0 +1,2 @@',
      '+++ bump',
      '+const real = 1;',
    ].join('\n');

    expect(parseUnifiedDiff(diff)).toEqual(new Map([['doc.md', new Set([1, 2])]]));
  });

  it('recovers the next file when a hunk declares more lines than it carries', () => {
    // A truncated hunk leaves `remaining` outstanding, which would make the NEXT
    // file's `+++ ` header read as content. `diff --git ` can never be hunk body
    // (every content line carries a prefix), so it resets the count.
    const diff = [
      'diff --git a/a.ts b/a.ts',
      '--- a/a.ts',
      '+++ b/a.ts',
      '@@ -0,0 +1,5 @@',
      '+const only = 1;',
      'diff --git a/b.ts b/b.ts',
      '--- a/b.ts',
      '+++ b/b.ts',
      '@@ -0,0 +1,1 @@',
      '+const second = 2;',
    ].join('\n');

    expect(parseUnifiedDiff(diff)).toEqual(
      new Map([
        ['a.ts', new Set([1])],
        ['b.ts', new Set([1])],
      ]),
    );
  });

  it('handles a new file with no a/ side', () => {
    const diff = [
      'diff --git a/src/new.ts b/src/new.ts',
      '--- /dev/null',
      '+++ b/src/new.ts',
      '@@ -0,0 +1,2 @@',
      '+const a = 1;',
      '+const b = 2;',
    ].join('\n');

    expect(parseUnifiedDiff(diff)).toEqual(new Map([['src/new.ts', new Set([1, 2])]]));
  });
});

describe('indexIstanbulReport', () => {
  it('takes the maximum hit count of the statements starting on a line', () => {
    // Two statements share line 3: one never ran, one ran twice. The line WAS
    // executed. Taking the first statement instead would report it uncovered,
    // which is how a short-circuited `a && b()` reads as dead code.
    const report = {
      '/abs/src/a.ts': {
        path: '/abs/src/a.ts',
        statementMap: {
          '0': { start: { line: 3 } },
          '1': { start: { line: 3 } },
          '2': { start: { line: 4 } },
        },
        s: { '0': 0, '1': 2, '2': 0 },
      },
    };

    const index = indexIstanbulReport(report, (p) => p.replace('/abs/', ''));

    expect(index.get('src/a.ts')).toEqual(
      new Map([
        [3, 2],
        [4, 0],
      ]),
    );
  });
});

describe('mergeCoverageIndexes', () => {
  it('takes the higher count when two packages measure the same file', () => {
    // A shared source file loaded by two suites: one exercises line 1, the
    // other does not. It is covered. Taking the lower would report a line as
    // untested because a second package merely imported the module.
    const merged = mergeCoverageIndexes([
      indexOf({ 'src/shared.ts': { 1: 5, 2: 0 } }),
      indexOf({ 'src/shared.ts': { 1: 0, 2: 0 } }),
    ]);

    expect(merged.get('src/shared.ts')).toEqual(
      new Map([
        [1, 5],
        [2, 0],
      ]),
    );
  });
});

describe('diffCoverage', () => {
  const coverage = indexOf({
    'src/a.ts': { 1: 3, 2: 0, 3: 0, 4: 1 },
    'src/b.ts': { 10: 1 },
  });

  it('counts only added lines that carry a statement', () => {
    // Line 99 is added but carries no statement — a comment, a blank, a closing
    // brace. Counting it as uncovered would drag every percentage toward the
    // formatting density rather than the testing.
    const added = new Map([['src/a.ts', new Set([1, 2, 99])]]);

    const result = diffCoverage(added, coverage);

    expect(result.eligible).toBe(2);
    expect(result.covered).toBe(1);
    expect(result.percent).toBe(50);
    expect(result.uncovered).toEqual(new Map([['src/a.ts', [2]]]));
  });

  it('reports a file no report measured as unmeasured, never as covered', () => {
    // The load-bearing case. If an unmeasured file were folded into `covered`,
    // a PR touching only excluded paths would report 100% while nothing ran.
    const added = new Map([['src/never-measured.ts', new Set([1, 2, 3])]]);

    const result = diffCoverage(added, coverage);

    expect(result.eligible).toBe(0);
    expect(result.covered).toBe(0);
    expect(result.percent).toBeNull();
    expect(result.unmeasured).toEqual(new Map([['src/never-measured.ts', [1, 2, 3]]]));
  });

  it('aggregates across files', () => {
    const added = new Map([
      ['src/a.ts', new Set([1, 2, 3, 4])],
      ['src/b.ts', new Set([10])],
    ]);

    const result = diffCoverage(added, coverage);

    expect(result.eligible).toBe(5);
    expect(result.covered).toBe(3);
    expect(result.uncovered).toEqual(new Map([['src/a.ts', [2, 3]]]));
  });
});

describe('parseNumericFlag', () => {
  it('falls back only when the flag was not supplied at all', () => {
    expect(parseNumericFlag(undefined, 80)).toBe(80);
  });

  it('reads a supplied number', () => {
    expect(parseNumericFlag('90', 80)).toBe(90);
    expect(parseNumericFlag('0', 80)).toBe(0);
    expect(parseNumericFlag('72.5', 80)).toBe(72.5);
  });

  it('refuses a value it cannot read rather than coercing it', () => {
    // The case this exists for. `Number('8O')` (letter O) is NaN, and every
    // comparison against NaN is false — so a mistyped floor does not fail the
    // run, it turns the gate OFF and reports a clean pass. Returning the
    // fallback here would be almost as bad: the run would silently gate at a
    // number nobody asked for.
    for (const bad of ['8O', 'abc', '', '   ', '-1', 'NaN', 'Infinity']) {
      expect(parseNumericFlag(bad, 80), `"${bad}" must be refused`).toBeNull();
    }
  });
});

describe('evaluateGate', () => {
  const options = { floor: 80, minimumLines: 25 };
  const resultWith = (eligible: number, covered: number) => ({
    eligible,
    covered,
    percent: eligible === 0 ? null : (covered / eligible) * 100,
    uncovered: new Map<string, number[]>(),
    unmeasured: new Map<string, number[]>(),
  });

  it('fails a large diff below the floor', () => {
    const verdict = evaluateGate(resultWith(100, 50), options);

    expect(verdict.passed).toBe(false);
    expect(verdict.reason).toContain('50.00%');
    expect(verdict.reason).toContain('below the 80% floor');
  });

  it('passes a large diff at the floor exactly', () => {
    // A boundary written as `<` rather than `<=`. Exactly at the floor is
    // meeting it; failing there makes the stated number a lie by one line.
    expect(evaluateGate(resultWith(100, 80), options).passed).toBe(true);
  });

  it('passes at a floor the percentage cannot represent exactly', () => {
    // 29/100 is exactly 29%, but (29/100)*100 evaluates to 28.999999999999996,
    // so a comparison on the PERCENTAGE fails a diff that meets its floor.
    // `Number.EPSILON` does not rescue it either — it is sized for values near
    // 1.0, and `80 + Number.EPSILON === 80`. Only the integer form is exact.
    // 80/100 (the case above) happens to round upward, which is why it passed
    // both before and after and cannot stand in for this one.
    expect(evaluateGate(resultWith(100, 29), { floor: 29, minimumLines: 25 }).passed).toBe(true);
    expect(evaluateGate(resultWith(1000, 289), { floor: 29, minimumLines: 25 }).passed).toBe(false);
  });

  it('reports but does not enforce below the minimum line count', () => {
    // A two-line diff can only score 0, 50 or 100. Enforcing 80% there means
    // "both lines or fail", which reddens typo fixes.
    const verdict = evaluateGate(resultWith(2, 1), options);

    expect(verdict.passed).toBe(true);
    expect(verdict.reason).toContain('advisory');
  });

  it('passes when nothing measurable changed', () => {
    const verdict = evaluateGate(resultWith(0, 0), options);

    expect(verdict.passed).toBe(true);
    expect(verdict.reason).toContain('nothing to measure');
  });
});

describe('formatLineRanges', () => {
  it('collapses runs and leaves singletons alone', () => {
    expect(formatLineRanges([1, 2, 3, 7, 9, 10])).toBe('1-3, 7, 9-10');
    expect(formatLineRanges([5])).toBe('5');
    expect(formatLineRanges([])).toBe('');
  });
});

describe('formatReport', () => {
  it('names the uncovered lines and keeps unmeasured files in their own section', () => {
    const result = {
      eligible: 4,
      covered: 2,
      percent: 50,
      uncovered: new Map([['src/a.ts', [2, 3]]]),
      unmeasured: new Map([['src/x.ts', [1]]]),
    };

    const report = formatReport(result, { passed: false, reason: 'below the floor' });

    expect(report).toContain('## Diff coverage');
    expect(report).toContain('❌ below the floor');
    expect(report).toContain('`src/a.ts` — 2-3');
    expect(report).toContain('`src/x.ts`');
    // The two must not be merged: an unmeasured file is not an uncovered line,
    // and presenting it as one sends people to write a test for an excluded
    // path.
    expect(report.indexOf('Uncovered changed lines')).toBeLessThan(
      report.indexOf('no coverage report measured'),
    );
  });
});
