import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { formatReport, isRelevantPath, type ScannedFile, scanTree } from '../src/lib.ts';

// Fixtures live in their own directory with a non-".test.ts" extension on
// purpose: a real run of check-portability.ts walks the tracked test tree, so
// a fixture written straight into THIS file (or named *.test.ts) would
// eventually get scanned by the tool it exists to test.
const FIXTURES_DIR = fileURLToPath(new URL('./fixtures', import.meta.url));

function fixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, name), 'utf8');
}

const testFile = (path: string, content: string): ScannedFile => ({ path, content });

describe('hardcoded-file-url', () => {
  it('flags a literal file:/// URL in a string', () => {
    const violations = scanTree([
      testFile('worker.test.ts', fixture('hardcoded-file-url.bad.txt')),
    ]);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({
      rule: 'hardcoded-file-url',
      file: 'worker.test.ts',
      line: 5,
    });
  });

  it('does not flag pathToFileURL', () => {
    expect(scanTree([testFile('worker.test.ts', fixture('hardcoded-file-url.clean.txt'))])).toEqual(
      [],
    );
  });

  it('does not flag the same text inside a // comment', () => {
    expect(
      scanTree([testFile('worker.test.ts', fixture('comment-mentions-file-url.txt'))]),
    ).toEqual([]);
  });

  it('does not flag its own test description, but still flags a real one in the same file', () => {
    const violations = scanTree([
      testFile('worker.test.ts', fixture('description-mentions-file-url.txt')),
    ]);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({
      rule: 'hardcoded-file-url',
      file: 'worker.test.ts',
      line: 9,
    });
  });
});

describe('bare-timeout-command', () => {
  it('flags a shell string invoking GNU timeout', () => {
    const violations = scanTree([testFile('probe.test.ts', fixture('bare-timeout.bad.txt'))]);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({
      rule: 'bare-timeout-command',
      file: 'probe.test.ts',
      line: 6,
    });
  });

  it('does not flag a vitest-style { timeout } option', () => {
    expect(scanTree([testFile('probe.test.ts', fixture('bare-timeout.clean.txt'))])).toEqual([]);
  });

  it('does not flag the same text inside a block comment', () => {
    expect(
      scanTree([testFile('probe.test.ts', fixture('block-comment-mentions-timeout.txt'))]),
    ).toEqual([]);
  });
});

describe('path-comparison-case', () => {
  it('flags two computed paths compared with no .toLowerCase()', () => {
    const violations = scanTree([testFile('paths.test.ts', fixture('path-comparison.bad.txt'))]);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({
      rule: 'path-comparison-case',
      file: 'paths.test.ts',
      line: 6,
    });
  });

  it('does not flag the comparison once both sides are lowercased', () => {
    expect(scanTree([testFile('paths.test.ts', fixture('path-comparison.clean.txt'))])).toEqual([]);
  });
});

describe('concurrency-missing-timeout', () => {
  it('flags a worker-spawning test with no timeout anywhere', () => {
    const violations = scanTree([
      testFile('scan.test.ts', fixture('concurrency-no-timeout.bad.txt')),
    ]);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({
      rule: 'concurrency-missing-timeout',
      file: 'scan.test.ts',
      line: 5,
    });
  });

  it('does not flag it once an inline numeric timeout is passed', () => {
    expect(
      scanTree([testFile('scan.test.ts', fixture('concurrency-no-timeout.clean.txt'))]),
    ).toEqual([]);
  });

  it('accepts an inline timeout written with numeric separators', () => {
    expect(
      scanTree([testFile('scan.test.ts', fixture('concurrency-timeout-separator.clean.txt'))]),
    ).toEqual([]);
  });

  it('accepts an inline timeout held in a named constant', () => {
    expect(
      scanTree([testFile('scan.test.ts', fixture('concurrency-timeout-constant.clean.txt'))]),
    ).toEqual([]);
  });

  it('accepts a named constant in the options-object form', () => {
    expect(
      scanTree([testFile('scan.test.ts', fixture('concurrency-options-constant.clean.txt'))]),
    ).toEqual([]);
  });

  it('still flags a trailing number too small to be a real timeout', () => {
    const violations = scanTree([
      testFile('scan.test.ts', fixture('concurrency-timeout-implausible.bad.txt')),
    ]);
    expect(violations).toHaveLength(1);
    expect(violations[0]?.rule).toBe('concurrency-missing-timeout');
  });

  // `\b` opens a boundary after the `.` in `SPEC_RE.test(`, so a member call
  // reads as a test declaration. That is not merely noisy: the block starts
  // mid-body and closes at the enclosing paren, so it carries the concurrency
  // primitive but never reaches the real call's trailing timeout — and the
  // false positive lands on a test that is correctly written, at the line of
  // the member call. The positive cases above are this one's control: they go
  // red if rule 4 stops firing altogether.
  it('does not mistake a .test() member call for a test declaration', () => {
    expect(
      scanTree([
        testFile('pkg/test/classify.test.ts', fixture('concurrency-member-call.clean.txt')),
      ]),
    ).toEqual([]);
  });

  it('is suppressed when the owning package sets a testTimeout override', () => {
    const files = [
      testFile('pkg/test/scan.test.ts', fixture('concurrency-no-timeout.bad.txt')),
      testFile('pkg/vitest.config.ts', 'export default { test: { testTimeout: 20000 } };'),
    ];
    expect(scanTree(files)).toEqual([]);
  });

  it('still fires when the package config has no testTimeout key', () => {
    const files = [
      testFile('pkg/test/scan.test.ts', fixture('concurrency-no-timeout.bad.txt')),
      testFile('pkg/vitest.config.ts', 'export default { test: { environment: "node" } };'),
    ];
    const violations = scanTree(files);
    expect(violations).toHaveLength(1);
    expect(violations[0]?.rule).toBe('concurrency-missing-timeout');
  });

  it("does not let one package's override suppress a different package", () => {
    const files = [
      testFile('pkg-a/test/scan.test.ts', fixture('concurrency-no-timeout.bad.txt')),
      testFile('pkg-b/vitest.config.ts', 'export default { test: { testTimeout: 20000 } };'),
    ];
    const violations = scanTree(files);
    expect(violations).toHaveLength(1);
    expect(violations[0]?.file).toBe('pkg-a/test/scan.test.ts');
  });
});

describe('regex literals', () => {
  it('does not mistake a quote inside a character class for a string, and keeps scanning correctly afterward', () => {
    const violations = scanTree([testFile('audit.test.ts', fixture('regex-with-quote-class.txt'))]);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({
      rule: 'hardcoded-file-url',
      file: 'audit.test.ts',
      line: 11,
    });
  });
});

describe('scanTree file selection', () => {
  it('ignores files that are not test files', () => {
    expect(scanTree([testFile('worker.ts', fixture('hardcoded-file-url.bad.txt'))])).toEqual([]);
  });

  it('scans .test.tsx and .test.js the same as .test.ts', () => {
    expect(
      scanTree([testFile('worker.test.tsx', fixture('hardcoded-file-url.bad.txt'))]),
    ).toHaveLength(1);
    expect(
      scanTree([testFile('worker.test.js', fixture('hardcoded-file-url.bad.txt'))]),
    ).toHaveLength(1);
  });

  it('applies rules 1-3 to a helper in a test tree, not just to a spec file', () => {
    const violations = scanTree([
      testFile('pkg/test/helpers/worker-url.ts', fixture('hardcoded-file-url.bad.txt')),
    ]);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({
      rule: 'hardcoded-file-url',
      file: 'pkg/test/helpers/worker-url.ts',
    });
  });

  // Rule 4 keys on an it()/test() call, which a helper does not own even when
  // it contains the text of one. The same bytes at a spec path are the control:
  // without it this case would pass on a rule that had stopped firing anywhere.
  it('does not apply rule 4 to a non-spec file, but still does at a spec path', () => {
    const helperBytes = fixture('concurrency-no-timeout.bad.txt');
    expect(scanTree([testFile('pkg/test/helpers/spawn.ts', helperBytes)])).toEqual([]);
    expect(scanTree([testFile('pkg/test/spawn.test.ts', helperBytes)])).toHaveLength(1);
  });

  it('applies rules 1-3 to a benchmark, which carries the same platform code as a spec', () => {
    const violations = scanTree([
      testFile('pkg/bench/project-files.bench.ts', fixture('hardcoded-file-url.bad.txt')),
    ]);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({
      rule: 'hardcoded-file-url',
      file: 'pkg/bench/project-files.bench.ts',
    });
  });

  // A .bench.ts is not a spec, so rule 4 stays off it for the reason it stays
  // off a helper. The same bytes at a spec path are the control.
  it('does not apply rule 4 to a benchmark, but still does at a spec path', () => {
    const bytes = fixture('concurrency-no-timeout.bad.txt');
    expect(scanTree([testFile('pkg/bench/scan.bench.ts', bytes)])).toEqual([]);
    expect(scanTree([testFile('pkg/test/scan.test.ts', bytes)])).toHaveLength(1);
  });

  it('leaves non-source files in a test tree alone, so fixtures stay safe', () => {
    const bytes = fixture('hardcoded-file-url.bad.txt');
    expect(scanTree([testFile('pkg/test/fixtures/bad.txt', bytes)])).toEqual([]);
    expect(scanTree([testFile('pkg/test/fixtures/bad.json', bytes)])).toEqual([]);
  });

  it('still ignores a source file outside any test tree', () => {
    expect(
      scanTree([testFile('pkg/src/worker.ts', fixture('hardcoded-file-url.bad.txt'))]),
    ).toEqual([]);
  });

  it('sorts violations by file then line', () => {
    const files = [
      testFile('z.test.ts', fixture('hardcoded-file-url.bad.txt')),
      testFile('a.test.ts', fixture('bare-timeout.bad.txt')),
    ];
    expect(scanTree(files).map((v) => v.file)).toEqual(['a.test.ts', 'z.test.ts']);
  });
});

// The pre-read filter the CLI entry walks git ls-files with. It decides what
// the scan can ever see, so a path scanTree would rule on but this rejects is
// a file the gate silently never reads.
describe('isRelevantPath', () => {
  it('accepts a spec file anywhere in the tree', () => {
    expect(isRelevantPath('pkg/test/scan.test.ts')).toBe(true);
    expect(isRelevantPath('pkg/src/scan.test.tsx')).toBe(true);
    expect(isRelevantPath('scan.test.js')).toBe(true);
  });

  it('accepts a source file under a test tree, at the repo root or nested', () => {
    expect(isRelevantPath('test/setup/no-network.ts')).toBe(true);
    expect(isRelevantPath('packages/persistence/test/helpers/fault-injection.ts')).toBe(true);
    expect(isRelevantPath('packages/eslint-config/test/helpers/lint-invocations.js')).toBe(true);
  });

  it('accepts every vitest.config.ts, which is how rule 4 finds an override', () => {
    expect(isRelevantPath('pkg/vitest.config.ts')).toBe(true);
    expect(isRelevantPath('vitest.config.ts')).toBe(true);
  });

  it('rejects non-source files and source outside a test tree', () => {
    expect(isRelevantPath('pkg/test/fixtures/corpus.txt')).toBe(false);
    expect(isRelevantPath('pkg/test/fixtures/rules.json')).toBe(false);
    expect(isRelevantPath('pkg/src/worker.ts')).toBe(false);
    expect(isRelevantPath('README.md')).toBe(false);
  });

  it('accepts a source file under a bench tree, at the repo root or nested', () => {
    expect(isRelevantPath('packages/plugin-sdk/bench/project-files.bench.ts')).toBe(true);
    expect(isRelevantPath('packages/persistence/bench/helpers/corpus.ts')).toBe(true);
    expect(isRelevantPath('bench/scan.bench.ts')).toBe(true);
  });

  it('does not treat a directory merely starting with "test" as a test tree', () => {
    expect(isRelevantPath('pkg/testing/helper.ts')).toBe(false);
    expect(isRelevantPath('pkg/test-utils/helper.ts')).toBe(false);
  });

  it('does not treat a directory merely starting with "bench" as a bench tree', () => {
    expect(isRelevantPath('pkg/benchmarks/helper.ts')).toBe(false);
    expect(isRelevantPath('pkg/bench-utils/helper.ts')).toBe(false);
  });

  // The tree predicate used to be one regex — `(?:^|/)test/.*\.(?:ts|…)$` —
  // which offers the engine a viable start position at every `/test/` segment
  // and rescans the tail from each, so a path that does NOT match costs time
  // quadratic in the segment count. This asserts elapsed time because
  // unbounded time is the whole defect, and because a synchronous call cannot
  // be cut short by vitest's own timeout: the body would run to completion and
  // report afterwards however low that timeout was set. The band is wide on
  // purpose rather than tuned — the regex form took ~2 s on this input and the
  // substring form takes microseconds, so anything in between separates them
  // and slow or loaded CI does not move it. The false assertion is the
  // positive control: a predicate short-circuiting to true would be fast too.
  it('answers a pathological path in linear time', () => {
    const hostile = `${'test/'.repeat(32_000)}x.txt`;
    const started = performance.now();
    expect(isRelevantPath(hostile)).toBe(false);
    expect(performance.now() - started).toBeLessThan(500);
  });

  // The CLI entry used to carry its own copy of this filter, which no test
  // reached — so the two could disagree about what the gate scans and only the
  // untested one decided. Pinning the call itself rather than the absence of a
  // regex is what makes that unrepeatable: any private filter, however spelled,
  // stops this from matching.
  it('is the only path filter the CLI entry has', () => {
    const entrySource = readFileSync(
      fileURLToPath(new URL('../src/check-portability.ts', import.meta.url)),
      'utf8',
    );
    expect(entrySource).toMatch(/trackedFiles\(\)\s*\.filter\(isRelevantPath\)/);
  });
});

describe('formatReport', () => {
  it('reports a clean scan', () => {
    expect(formatReport([])).toBe('Portability check passed: no violations found.');
  });

  it('lists file, line, rule and message for each violation', () => {
    const report = formatReport([
      { rule: 'hardcoded-file-url', file: 'a.test.ts', line: 3, message: 'because reasons' },
    ]);
    expect(report).toContain('1 violation');
    expect(report).toContain('a.test.ts:3');
    expect(report).toContain('[hardcoded-file-url]');
    expect(report).toContain('because reasons');
  });
});
