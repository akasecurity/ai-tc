import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  DEFAULT_FLOOR,
  DEFAULT_MINIMUM_LINES,
  findFlag,
  type GateIo,
  type IstanbulFileCoverage,
  parseManifestList,
  resolveNumericFlag,
  runGate,
  selectCoverageReports,
  toRepoRelative,
} from '../src/lib.ts';

/**
 * Built with `resolve` rather than written as a literal, so the fixtures carry
 * the host's own separator and drive `toRepoRelative`'s normalization for real
 * on Windows instead of asserting POSIX input produces POSIX output.
 */
const ROOT = resolve('/repo');
const abs = (...parts: string[]): string => resolve(ROOT, ...parts);

describe('findFlag', () => {
  it('reads the space-separated form', () => {
    expect(findFlag('base', ['node', 'gate', '--base', 'origin/main'])).toBe('origin/main');
  });

  it('reads the inline form', () => {
    expect(findFlag('base', ['node', 'gate', '--base=origin/main'])).toBe('origin/main');
  });

  it('returns undefined for a flag that is absent', () => {
    expect(findFlag('base', ['node', 'gate', '--floor', '80'])).toBeUndefined();
  });

  it('returns undefined when the flag is the last argv entry', () => {
    expect(findFlag('base', ['node', 'gate', '--base'])).toBeUndefined();
  });

  // The case above cannot prove the bounds check on its own: reading argv off
  // the end yields undefined, which is the same answer the check produces, so it
  // passes with the check deleted. This one discriminates — a bare `--base` last
  // must fall THROUGH to the inline form rather than returning the void past it.
  it('falls through to the inline form when the bare flag is last', () => {
    expect(findFlag('base', ['node', 'gate', '--base=origin/main', '--base'])).toBe('origin/main');
  });

  it('does not match a flag whose name merely starts the same', () => {
    expect(findFlag('floor', ['node', 'gate', '--floorish=3'])).toBeUndefined();
    expect(findFlag('minimum', ['node', 'gate', '--minimum-lines', '4'])).toBeUndefined();
  });

  // `--name=` is a SUPPLIED empty value, not an absent flag. Collapsing the two
  // would send it to the fallback instead of to parseNumericFlag's refusal.
  it('reads an inline empty value as empty rather than absent', () => {
    expect(findFlag('floor', ['node', 'gate', '--floor='])).toBe('');
  });
});

describe('resolveNumericFlag', () => {
  it('falls back when the flag is absent', () => {
    expect(resolveNumericFlag('floor', ['node', 'gate'], 80)).toBe(80);
  });

  it('reads a supplied value', () => {
    expect(resolveNumericFlag('floor', ['node', 'gate', '--floor', '55'], 80)).toBe(55);
  });

  it('refuses a supplied value it cannot read, rather than falling back', () => {
    expect(resolveNumericFlag('floor', ['node', 'gate', '--floor', 'abc'], 80)).toBeNull();
    expect(resolveNumericFlag('floor', ['node', 'gate', '--floor='], 80)).toBeNull();
  });
});

describe('toRepoRelative', () => {
  it('maps an absolute path to a repo-relative POSIX path', () => {
    expect(toRepoRelative(abs('tools', 'coverage-gate', 'src', 'lib.ts'), ROOT)).toBe(
      'tools/coverage-gate/src/lib.ts',
    );
  });
});

describe('parseManifestList', () => {
  it('drops blank lines and vendored manifests', () => {
    expect(
      parseManifestList(
        [
          'cli/package.json',
          '',
          'web-ui/node_modules/x/package.json',
          'packages/a/package.json',
        ].join('\n'),
      ),
    ).toEqual(['cli/package.json', 'packages/a/package.json']);
  });
});

describe('selectCoverageReports', () => {
  const lookupOver = (
    manifests: Record<string, { test?: boolean }>,
    present: readonly string[],
  ) => ({
    root: ROOT,
    readFile: (path: string) => {
      const key = toRepoRelative(path, ROOT);
      const entry = manifests[key];
      if (entry === undefined) throw new Error(`unexpected read: ${key}`);
      return JSON.stringify(entry.test === true ? { scripts: { test: 'vitest run' } } : {});
    },
    exists: (path: string) => present.includes(toRepoRelative(path, ROOT)),
  });

  it('collects a report for each package that declares a test script', () => {
    const selection = selectCoverageReports(['a/package.json'], {
      ...lookupOver({ 'a/package.json': { test: true } }, ['a/coverage/coverage-final.json']),
    });
    expect(selection.reports).toEqual([abs('a', 'coverage', 'coverage-final.json')]);
    expect(selection.missing).toEqual([]);
  });

  // The direction a coverage gate must not fail in: a package dropped from the
  // denominator makes the number too HIGH, so an absent report is reported, not
  // skipped.
  it('reports a test-running package that wrote no report as missing', () => {
    const selection = selectCoverageReports(['a/package.json'], {
      ...lookupOver({ 'a/package.json': { test: true } }, []),
    });
    expect(selection.reports).toEqual([]);
    expect(selection.missing).toEqual(['a/coverage/coverage-final.json']);
  });

  it('ignores a package with no test script entirely', () => {
    const selection = selectCoverageReports(['a/package.json'], {
      ...lookupOver({ 'a/package.json': {} }, []),
    });
    expect(selection.reports).toEqual([]);
    expect(selection.missing).toEqual([]);
  });
});

/** One statement per line, with the given hit counts. */
const fileCoverage = (path: string, hitsByLine: Record<number, number>): IstanbulFileCoverage => {
  const statementMap: Record<string, { start: { line: number } }> = {};
  const s: Record<string, number> = {};
  for (const [index, [line, hits]] of Object.entries(hitsByLine).entries()) {
    statementMap[String(index)] = { start: { line: Number(line) } };
    s[String(index)] = hits;
  }
  return { path, statementMap, s };
};

const DIFF_TWO_LINES = [
  'diff --git a/src/a.ts b/src/a.ts',
  '--- a/src/a.ts',
  '+++ b/src/a.ts',
  '@@ -0,0 +1,2 @@',
  '+const a = 1;',
  '+const b = 2;',
  '',
].join('\n');

interface Harness {
  code: number;
  out: string;
  err: string;
  summaries: [string, string][];
  gitCalls: string[][];
}

/** Drive runGate over canned git output and a canned filesystem. */
function drive(options: {
  argv?: readonly string[];
  manifestTest?: boolean;
  reportPresent?: boolean;
  hits?: Record<number, number>;
  diff?: string;
  throwOn?: 'ls-files' | 'merge-base';
}): Harness {
  const {
    argv = [],
    manifestTest = true,
    reportPresent = true,
    hits = { 1: 1, 2: 1 },
    diff = DIFF_TWO_LINES,
    throwOn,
  } = options;

  const out: string[] = [];
  const err: string[] = [];
  const summaries: [string, string][] = [];
  const gitCalls: string[][] = [];
  const reportPath = abs('a', 'coverage', 'coverage-final.json');

  const io: GateIo = {
    argv: ['node', 'gate', ...argv],
    root: ROOT,
    git: (args) => {
      gitCalls.push([...args]);
      if (throwOn !== undefined && args[0]?.includes(throwOn) === true) {
        throw new Error(`git ${throwOn} failed`);
      }
      if (args[0] === 'ls-files') return 'a/package.json\n';
      if (args[0] === 'merge-base') return 'abc123\n';
      return diff;
    },
    readFile: (path) => {
      if (path === reportPath) {
        return JSON.stringify({ [abs('src', 'a.ts')]: fileCoverage(abs('src', 'a.ts'), hits) });
      }
      return JSON.stringify(manifestTest ? { scripts: { test: 'vitest run' } } : {});
    },
    exists: () => reportPresent,
    writeOut: (text) => out.push(text),
    writeErr: (text) => err.push(text),
    appendSummary: (file, text) => summaries.push([file, text]),
  };

  return { code: runGate(io), out: out.join(''), err: err.join(''), summaries, gitCalls };
}

describe('runGate', () => {
  it('clears the floor when every changed line is covered', () => {
    const r = drive({ argv: ['--minimum-lines', '1'] });
    expect(r.code).toBe(0);
    expect(r.out).toContain('✅');
    expect(r.out).toContain('100.00% of 2 changed lines covered');
    expect(r.err).toBe('');
  });

  it('fails below the floor and names the uncovered lines', () => {
    const r = drive({ argv: ['--minimum-lines', '1'], hits: { 1: 1, 2: 0 } });
    expect(r.code).toBe(1);
    expect(r.out).toContain('❌');
    expect(r.out).toContain('50.00% of 2 changed lines covered, below the 80% floor.');
    expect(r.out).toContain('`src/a.ts` — 2');
  });

  it('honours an explicit --floor', () => {
    const r = drive({ argv: ['--minimum-lines', '1', '--floor', '50'], hits: { 1: 1, 2: 0 } });
    expect(r.code).toBe(0);
    expect(r.out).toContain('(floor 50%)');
  });

  // Exit 2, distinct from the exit 1 a real shortfall produces: a flag that was
  // supplied and could not be read is a mistake in the invocation, not a verdict
  // about the diff.
  it('refuses an unreadable --floor with exit 2, naming the flag', () => {
    const r = drive({ argv: ['--floor', 'abc'] });
    expect(r.code).toBe(2);
    expect(r.err).toContain('--floor must be a non-negative number, got "abc"');
    expect(r.out).toBe('');
  });

  it('refuses an unreadable --minimum-lines with exit 2', () => {
    const r = drive({ argv: ['--minimum-lines', '-4'] });
    expect(r.code).toBe(2);
    expect(r.err).toContain('--minimum-lines must be a non-negative number, got "-4"');
  });

  it('is fatal when a test-running package wrote no report', () => {
    const r = drive({ reportPresent: false });
    expect(r.code).toBe(1);
    expect(r.err).toContain('no coverage report for:');
    expect(r.err).toContain('a/coverage/coverage-final.json');
    expect(r.err).toContain('Run `pnpm turbo run test` first');
    expect(r.out).toBe('');
  });

  it('reports a broken git rather than throwing a child_process stack', () => {
    const r = drive({ throwOn: 'ls-files' });
    expect(r.code).toBe(1);
    expect(r.err).toContain('cannot enumerate packages:');
    expect(r.err).toContain('git ls-files failed');
  });

  it('reports an unreachable merge base with the fetch hint', () => {
    const r = drive({ throwOn: 'merge-base' });
    expect(r.code).toBe(1);
    expect(r.err).toContain('cannot resolve a merge base with "origin/main"');
    expect(r.err).toContain('actions/checkout uses depth 1 by default');
  });

  it('diffs from the merge base with the pinned prefixes, three-dot', () => {
    const r = drive({ argv: ['--minimum-lines', '1', '--base', 'origin/release'] });
    expect(r.gitCalls).toContainEqual(['merge-base', 'origin/release', 'HEAD']);
    const diffCall = r.gitCalls.find((c) => c[0] === 'diff');
    expect(diffCall).toEqual([
      'diff',
      '--unified=0',
      '--no-color',
      '--no-ext-diff',
      '--src-prefix=a/',
      '--dst-prefix=b/',
      'abc123...HEAD',
    ]);
  });

  it('appends the same report it printed to the summary file', () => {
    const r = drive({ argv: ['--minimum-lines', '1', '--summary', '/tmp/summary.md'] });
    expect(r.summaries).toHaveLength(1);
    expect(r.summaries[0]?.[0]).toBe('/tmp/summary.md');
    expect(r.summaries[0]?.[1]).toBe(r.out);
  });

  it('writes no summary when the flag is absent', () => {
    expect(drive({ argv: ['--minimum-lines', '1'] }).summaries).toEqual([]);
  });

  // The advisory band: a change too small for a percentage to describe passes
  // and says so, rather than being asked for 80% of three lines.
  it('reports but does not enforce below the minimum-lines band', () => {
    const r = drive({ hits: { 1: 0, 2: 0 } });
    expect(r.code).toBe(0);
    expect(r.out).toContain('advisory');
  });
});

describe('defaults', () => {
  it('are the values the gate documents', () => {
    expect(DEFAULT_FLOOR).toBe(80);
    expect(DEFAULT_MINIMUM_LINES).toBe(25);
  });
});
