import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  formatReport,
  GRANDFATHERED_PLATFORM_GUARDS,
  isRelevantPath,
  resolveGrandfatheredGuards,
  type ScannedFile,
  scanTree,
} from '../src/lib.ts';

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

describe('path-separator-literal', () => {
  // The shim that motivated this rule lives in a HELPER, not a *.test.ts, so
  // every case here is filed under a test-tree path rather than a spec name —
  // a bare "harness.ts" is neither, and scanTree would skip it, passing each
  // absence assertion below without ever running the rule.
  const HELPER = 'plugins/x/test/journey/harness.ts';

  it('flags a template join, a .join(":") and a .split(":") on PATH', () => {
    const violations = scanTree([testFile(HELPER, fixture('path-separator.bad.txt'))]).filter(
      (v) => v.rule === 'path-separator-literal',
    );
    expect(violations.map((v) => v.line)).toEqual([8, 11, 12]);
    expect(violations[0]?.message).toContain('path.delimiter');
  });

  it('does not flag path.delimiter, nor a colon-joined string naming no PATH', () => {
    expect(scanTree([testFile(HELPER, fixture('path-separator.clean.txt'))])).toEqual([]);
  });

  it('flags it in a spec file too', () => {
    const violations = scanTree([
      testFile('shim.test.ts', fixture('path-separator.bad.txt')),
    ]).filter((v) => v.rule === 'path-separator-literal');
    expect(violations).toHaveLength(3);
  });

  it('reports a multi-line template at the separator s line, not where the literal opens', () => {
    // A string segment's line is only where it OPENS. A template that spans
    // lines carries its `}:${` further down, and reporting the opening line
    // sends the reader somewhere the defect is not.
    const violations = scanTree([
      testFile(
        HELPER,
        ['const env = {', '  PATH: `${binDir}', '${middle}:${hostPath}`,', '};'].join('\n'),
      ),
    ]).filter((v) => v.rule === 'path-separator-literal');
    expect(violations.map((v) => v.line)).toEqual([3]);
  });

  it('reports one violation per line however many literals sit on it', () => {
    const violations = scanTree([
      testFile(HELPER, "const round = process.env.PATH.split(':').join(':');"),
    ]).filter((v) => v.rule === 'path-separator-literal');
    expect(violations).toHaveLength(1);
  });

  it('does not flag the same shape inside a comment', () => {
    const violations = scanTree([
      testFile(
        HELPER,
        [
          '// PATH: `${binDir}:${rest}` is the POSIX-only form this rule catches.',
          'export const x = 1;',
        ].join('\n'),
      ),
    ]);
    expect(violations).toEqual([]);
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

describe('platform-guard-early-return', () => {
  // A real spec path: the allowance cases below all assert on a SHORT violation
  // list, so a path scanTree skips outright satisfies them without the rule ever
  // running. The bytes are built here rather than read from a fixture because
  // the string literal is masked out of this file's own scan.
  const SPEC = 'pkg/test/legacy.test.ts';
  const guards = (n: number): string =>
    Array.from({ length: n }, () => "if (process.platform === 'win32') return;").join('\n');

  // The last two are the comment-bearing blocks. They matter because a comment
  // is the most natural thing to write next to a bail-out, and the rule locates
  // its candidate on masked text precisely so one cannot hide the defect —
  // matching structure against the raw source instead leaves both unflagged.
  it('flags the one-line form, the block form, the !== form and a commented block', () => {
    const violations = scanTree([
      testFile('paths.test.ts', fixture('platform-guard-return.bad.txt')),
    ]);
    expect(violations.map((v) => v.line)).toEqual([7, 12, 19, 26, 34]);
    expect(violations.every((v) => v.rule === 'platform-guard-early-return')).toBe(true);
    expect(violations[0]?.message).toContain('ctx.skip');
  });

  // Five shapes at once, and each is load-bearing. ctx.skip + return is the
  // fixed form, so flagging it would make the rule unsatisfiable. The positive
  // conditional is the fix for a test that still asserts something on the
  // guarded platform. it.skipIf reports as a skip already. And `return
  // '<reason>';` is a helper handing back a value — in both the one-line and the
  // block spelling, which pull against each other: the block is only reachable
  // by matching on masked text, and only reading the RAW source there keeps the
  // returned literal visible enough to exempt it.
  it('does not flag ctx.skip, a positive conditional, it.skipIf, or a returned value', () => {
    expect(
      scanTree([testFile('paths.test.ts', fixture('platform-guard-return.clean.txt'))]),
    ).toEqual([]);
  });

  it('does not flag the same shape inside a comment', () => {
    const violations = scanTree([
      testFile(
        'paths.test.ts',
        [
          "// if (process.platform === 'win32') return; is what this rule catches.",
          'const x = 1;',
        ].join('\n'),
      ),
    ]);
    expect(violations).toEqual([]);
  });

  // The defect is a TEST reporting a pass, which a helper does not do. The same
  // bytes at a spec path are the control: without it this case would pass on a
  // rule that had stopped firing anywhere.
  it('does not apply to a non-spec file, but still does at a spec path', () => {
    const bytes = fixture('platform-guard-return.bad.txt');
    expect(scanTree([testFile('pkg/test/helpers/modes.ts', bytes)])).toEqual([]);
    expect(scanTree([testFile('pkg/test/modes.test.ts', bytes)])).toHaveLength(5);
  });

  it('exempts a grandfathered file up to its allowance', () => {
    const files = [testFile(SPEC, guards(3))];
    expect(scanTree(files, { grandfatheredPlatformGuards: { [SPEC]: 3 } })).toEqual([]);
  });

  // Reported at the LAST guard rather than the first: the allowance covers what
  // was already there, so the new one is on the end, and that is the line whose
  // author needs to read the message.
  it('flags the guard past the allowance, at its own line', () => {
    const violations = scanTree([testFile(SPEC, guards(3))], {
      grandfatheredPlatformGuards: { [SPEC]: 2 },
    });
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ rule: 'platform-guard-early-return', line: 3 });
  });

  // The ratchet's other direction. Without this an allowance stays at its
  // original number for ever, so converting two of three guards silently leaves
  // room for two new ones — an exemption that grows back.
  it('reports a stale allowance when the file carries fewer than it allows', () => {
    const violations = scanTree([testFile(SPEC, guards(1))], {
      grandfatheredPlatformGuards: { [SPEC]: 3 },
    });
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ rule: 'platform-guard-stale-allowance', line: 1 });
    expect(violations[0]?.message).toContain('carries 1');
  });

  // The shipped map is empty, so nothing distinguishes omitting the option from
  // passing {} — both exempt nothing — and a case driving the default through it
  // could only hold vacuously. What is left to pin is the emptiness itself: an
  // entry here exempts a real guard in a real spec file, so re-adding one is a
  // deliberate edit with a reason rather than a line that slips in beside a
  // conversion. The arithmetic behind the allowance is covered by the injected-map
  // cases above, which is why emptying this does not retire the mechanism.
  it('ships an empty allowance map — no spec file is exempt from rule 6', () => {
    // Object.keys rather than toEqual({}), which is satisfied by an entry whose
    // value is undefined — the declared type is otherwise all that rules one out.
    expect(Object.keys(GRANDFATHERED_PLATFORM_GUARDS)).toEqual([]);
    // The control: with nothing exempt, a guard at any spec path is reported on
    // the default map, which is the behaviour an entry would take away. It pins
    // the RULE and not just the count — these bytes are also a same-line path
    // comparison, so a count alone would survive rule 6 going silent while rule 4
    // fired in its place.
    const violations = scanTree([testFile(SPEC, guards(1))]);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ rule: 'platform-guard-early-return', line: 1 });
  });

  // The default above is unobservable through scanTree's output while the map is
  // empty, so the binding is pinned by identity instead: `{}` is not the shipped
  // constant, and Object.is separates them where a value comparison could not.
  it('defaults to the shipped allowance map, and prefers an explicit one', () => {
    expect(resolveGrandfatheredGuards({})).toBe(GRANDFATHERED_PLATFORM_GUARDS);
    const injected = { [SPEC]: 1 };
    expect(resolveGrandfatheredGuards({ grandfatheredPlatformGuards: injected })).toBe(injected);
  });

  // ...and that the scan actually goes through it, which the case above does NOT
  // cover: it never calls scanTree, and scanTree inlining `?? {}` instead is
  // invisible in its output for the same reason the helper exists. So the last
  // link is asserted against the source, the shape this repo reaches for where
  // behaviour cannot (plugin-sdk's data-dir.test.ts pins its mode constants the
  // same way). Ugly, and load-bearing only while the shipped map is empty — once
  // an exemption is added, a behavioural case can replace this outright.
  it('resolves the allowance map through that helper, not a second inline default', () => {
    const source = readFileSync(new URL('../src/lib.ts', import.meta.url), 'utf8');
    expect(source).toContain('const grandfathered = resolveGrandfatheredGuards(options);');
    // Exactly one place resolves the default, so a second one reintroduced beside
    // the call above is caught too. Both assertions read RAW source, comments
    // included — an absence assertion here would fire on prose that merely names
    // the shape it forbids, which is why this pins what must be PRESENT instead.
    // (The gate masks comments before matching for the same reason; that
    // machinery is internal, and a two-line guard does not earn exporting it.)
    expect(source.match(/\?\? GRANDFATHERED_PLATFORM_GUARDS/g)).toHaveLength(1);
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
