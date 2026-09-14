/**
 * Diff coverage: of the lines this change ADDS or MODIFIES, how many does the
 * suite actually execute?
 *
 * A repository-wide percentage is the wrong instrument on a tree this size. It
 * moves by fractions on any single PR, so it can neither pass nor fail one
 * honestly — and it is trivially bought: adding a well-covered module raises it
 * while the untested Server Action beside it stays untested. The number that
 * describes a change is the one taken over the change.
 *
 * Everything here is pure over its inputs — a diff string, a set of coverage
 * reports, an argv array — or pure over INJECTED seams (see GateIo), so every
 * branch is drivable from a fixture. The CLI entry (check-diff-coverage.ts)
 * owns all I/O — running git, reading files, writing stdout — and decides
 * nothing, so the decisions stay next to the tests that drive them.
 */
import { relative, resolve, sep } from 'node:path';

/** A file's added/modified line numbers, keyed by repo-relative posix path. */
export type AddedLines = Map<string, Set<number>>;

/** Per-line execution counts for one file. */
export type LineHits = Map<number, number>;

/** Execution counts for every measured file, keyed by repo-relative posix path. */
export type CoverageIndex = Map<string, LineHits>;

/** The istanbul-shaped JSON `@vitest/coverage-v8` writes as `coverage-final.json`. */
export interface IstanbulFileCoverage {
  path?: string;
  statementMap?: Record<string, { start?: { line?: number } }>;
  s?: Record<string, number>;
}

export interface DiffCoverageResult {
  /** Lines that are both added by the diff and present in a coverage report. */
  eligible: number;
  covered: number;
  /** `covered / eligible` as a percentage; `null` when nothing was eligible. */
  percent: number | null;
  /** Eligible-but-unexecuted lines, keyed by file, ascending. */
  uncovered: Map<string, number[]>;
  /**
   * Added lines in files no report measured — an EXCLUDED or UNMEASURED file,
   * not a covered one. Counted separately and never folded into `covered`,
   * because silently treating "not measured" as "fine" is the one way this gate
   * can report a clean number over untested code.
   */
  unmeasured: Map<string, number[]>;
}

/**
 * Added/modified line numbers per file, parsed from `git diff --unified=0`.
 *
 * Only the `+` side is read: a deleted line has no coverage to have, and a
 * context line belongs to code this change did not write. Renames arrive as
 * `+++ b/<new path>` so the new path is what gets attributed, which is correct —
 * the lines are new at that path.
 */
export function parseUnifiedDiff(diff: string): AddedLines {
  const added: AddedLines = new Map();
  let file: string | undefined;
  let nextLine = 0;
  let remaining = 0;

  for (const raw of diff.split('\n')) {
    // `diff --git ` is the one unambiguous boundary: every line inside a hunk
    // body carries a +/-/space prefix, so this can never be content. It also
    // clears any hunk left outstanding by a truncated diff, which is what stops
    // one malformed hunk from swallowing the header of the next file.
    if (raw.startsWith('diff --git ')) {
      remaining = 0;
      continue;
    }

    // `+++ ` and `--- ` are headers ONLY outside a hunk body. Inside one they
    // are ordinary content: an added line reading `++ bump` is emitted as
    // `+++ bump`, and reading that as a header drops the real file from the diff
    // entirely while inventing a phantom path from the rest of the line.
    // `remaining` is the hunk's declared added-line count, so it is zero exactly
    // when no hunk body is outstanding — which is where every real header sits.
    if (remaining === 0 && raw.startsWith('+++ ')) {
      const target = raw.slice(4).trim();
      // /dev/null is a deletion — nothing to attribute.
      file = target === '/dev/null' ? undefined : stripDiffPrefix(target);
      continue;
    }
    if (remaining === 0 && raw.startsWith('--- ')) continue;

    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(raw);
    if (hunk) {
      nextLine = Number(hunk[1]);
      // A hunk header with no count means one line; `+n,0` is a pure deletion.
      remaining = hunk[2] === undefined ? 1 : Number(hunk[2]);
      continue;
    }

    if (remaining > 0 && raw.startsWith('+') && file !== undefined) {
      let lines = added.get(file);
      if (!lines) {
        lines = new Set();
        added.set(file, lines);
      }
      lines.add(nextLine);
      nextLine += 1;
      remaining -= 1;
    }
  }

  return added;
}

/**
 * `b/src/x.ts` -> `src/x.ts`.
 *
 * No separator rewriting happens here: git emits POSIX separators in diff
 * headers on every platform, so a backslash in this string is part of the
 * FILENAME (or of git's own quoting), never a Windows separator. Rewriting one
 * would corrupt the path rather than normalise it.
 *
 * Git quotes a path containing unusual bytes and escapes it; those are left
 * alone rather than half-decoded, since a path this cannot resolve should miss
 * the coverage index (and be reported as unmeasured) rather than silently match
 * the wrong file.
 *
 * The `a/`/`b/` prefixes are pinned on the git invocation (`--src-prefix`,
 * `--dst-prefix`) so this strip cannot be turned into a mis-strip by a user's
 * `diff.noprefix`, which would otherwise eat a real top-level `a/` directory.
 */
function stripDiffPrefix(target: string): string {
  return /^[ab]\//.exec(target) ? target.slice(2) : target;
}

/**
 * Fold one `coverage-final.json` into a per-line index.
 *
 * The line count is the MAXIMUM hit count of the statements starting on that
 * line, which is what istanbul's own `getLineCoverage` does. Taking the first
 * statement instead would report a line as uncovered whenever a short-circuited
 * expression shares it with an executed one.
 */
export function indexIstanbulReport(
  report: Record<string, IstanbulFileCoverage>,
  toRepoRelative: (absolute: string) => string,
): CoverageIndex {
  const index: CoverageIndex = new Map();

  for (const [key, file] of Object.entries(report)) {
    const absolute = file.path ?? key;
    const relative = toRepoRelative(absolute);
    const statements = file.statementMap ?? {};
    const counts = file.s ?? {};

    let hits = index.get(relative);
    if (!hits) {
      hits = new Map();
      index.set(relative, hits);
    }

    for (const [id, entry] of Object.entries(statements)) {
      const line = entry.start?.line;
      if (typeof line !== 'number') continue;
      const count = counts[id] ?? 0;
      const previous = hits.get(line);
      if (previous === undefined || previous < count) hits.set(line, count);
    }
  }

  return index;
}

/**
 * Merge per-package indexes into one.
 *
 * A file measured by two packages (a source file imported across a wall) takes
 * the higher count per line: it WAS executed, by somebody's suite. Taking the
 * lower would report a line as untested because a second package that happens
 * not to exercise it also loaded it.
 */
export function mergeCoverageIndexes(indexes: readonly CoverageIndex[]): CoverageIndex {
  const merged: CoverageIndex = new Map();

  for (const index of indexes) {
    for (const [file, hits] of index) {
      let target = merged.get(file);
      if (!target) {
        target = new Map();
        merged.set(file, target);
      }
      for (const [line, count] of hits) {
        const previous = target.get(line);
        if (previous === undefined || previous < count) target.set(line, count);
      }
    }
  }

  return merged;
}

/**
 * Diff coverage over the added lines a coverage report can speak to.
 *
 * A line is eligible when its file was measured AND the report carries a
 * statement starting on that line. A blank line, a comment, an import-only line
 * and a closing brace all carry no statement, so counting them would drag every
 * percentage toward the density of the formatting rather than the testing.
 */
export function diffCoverage(added: AddedLines, coverage: CoverageIndex): DiffCoverageResult {
  let eligible = 0;
  let covered = 0;
  const uncovered = new Map<string, number[]>();
  const unmeasured = new Map<string, number[]>();

  // Codepoint order, not `localeCompare`: the report has to read the same on a
  // developer's machine and on the runner, and localeCompare without an explicit
  // locale orders punctuation and case by the host's.
  for (const [file, lines] of [...added].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    const hits = coverage.get(file);
    if (!hits) {
      unmeasured.set(
        file,
        [...lines].sort((a, b) => a - b),
      );
      continue;
    }

    const missed: number[] = [];
    for (const line of [...lines].sort((a, b) => a - b)) {
      const count = hits.get(line);
      if (count === undefined) continue; // no statement here — not code
      eligible += 1;
      if (count > 0) covered += 1;
      else missed.push(line);
    }
    if (missed.length > 0) uncovered.set(file, missed);
  }

  return {
    eligible,
    covered,
    percent: eligible === 0 ? null : (covered / eligible) * 100,
    uncovered,
    unmeasured,
  };
}

export interface GateOptions {
  /** Percentage a diff must reach. */
  floor: number;
  /**
   * Eligible-line count below which the percentage is reported but not enforced.
   *
   * On a two-line diff the only reachable scores are 0, 50 and 100, so a floor
   * of 80 means "both lines or fail" — which reddens typo fixes and teaches
   * people to route around the gate. Above this many lines the number says
   * something, so it binds.
   */
  minimumLines: number;
}

export interface GateVerdict {
  passed: boolean;
  /** Why, in one line, for the CI summary. */
  reason: string;
}

/**
 * A numeric flag value, or `null` when it is not one.
 *
 * Lives here rather than beside the argv reader so it is drivable from a
 * fixture, because the case that matters is the one nobody types on purpose:
 * `Number('8O')` is NaN, and every comparison against NaN is false — so a
 * mistyped `--floor` would not fail the run, it would turn the gate OFF and
 * report a clean pass. A gate that silently stops gating is worse than no gate,
 * because the green check goes on being read as evidence. Returning `null`
 * rather than a fallback is deliberate: a value that was SUPPLIED and cannot be
 * read is a mistake to surface, not one to paper over with a default.
 */
export function parseNumericFlag(raw: string | undefined, fallback: number): number | null {
  if (raw === undefined) return fallback;
  const value = Number(raw);
  // Rejects NaN and both infinities; `Number('')` is 0, so an empty value is
  // refused separately rather than silently reading as a floor of zero.
  if (raw.trim() === '' || !Number.isFinite(value) || value < 0) return null;
  return value;
}

/** Whether a diff-coverage result clears the gate. */
export function evaluateGate(result: DiffCoverageResult, options: GateOptions): GateVerdict {
  if (result.percent === null) {
    return { passed: true, reason: 'No covered-file lines changed — nothing to measure.' };
  }
  const percent = result.percent.toFixed(2);
  if (result.eligible < options.minimumLines) {
    return {
      passed: true,
      reason:
        `${percent}% of ${String(result.eligible)} changed lines covered — advisory: ` +
        `under the ${String(options.minimumLines)}-line floor where the percentage is meaningful.`,
    };
  }
  // Compared as integers rather than on the percentage, because the percentage
  // is a float and the float is not reliably >= the floor even when the ratio
  // exactly meets it: (29/100)*100 evaluates to 28.999999999999996, so an exact
  // 29% against a floor of 29 reads as below it. `Number.EPSILON` does not fix
  // that — it is sized for values near 1.0, and `80 + Number.EPSILON === 80`.
  // covered/eligible >= floor/100  <=>  covered * 100 >= floor * eligible, and
  // both sides here are exact for any diff this repository will ever see.
  if (result.covered * 100 < options.floor * result.eligible) {
    return {
      passed: false,
      reason:
        `${percent}% of ${String(result.eligible)} changed lines covered, ` +
        `below the ${String(options.floor)}% floor.`,
    };
  }
  return {
    passed: true,
    reason:
      `${percent}% of ${String(result.eligible)} changed lines covered ` +
      `(floor ${String(options.floor)}%).`,
  };
}

/** The per-PR report, as GitHub-flavoured markdown for the step summary. */
export function formatReport(result: DiffCoverageResult, verdict: GateVerdict): string {
  const lines: string[] = [
    '## Diff coverage',
    '',
    `${verdict.passed ? '✅' : '❌'} ${verdict.reason}`,
  ];

  if (result.eligible > 0) {
    lines.push(
      '',
      '| Changed lines | Covered | Uncovered |',
      '| ------------: | ------: | --------: |',
      `| ${String(result.eligible)} | ${String(result.covered)} | ${String(result.eligible - result.covered)} |`,
    );
  }

  if (result.uncovered.size > 0) {
    lines.push('', '### Uncovered changed lines', '');
    for (const [file, missed] of result.uncovered) {
      lines.push(`- \`${file}\` — ${formatLineRanges(missed)}`);
    }
  }

  if (result.unmeasured.size > 0) {
    lines.push(
      '',
      '### Changed files no coverage report measured',
      '',
      'Excluded from coverage, or shipped by a package whose suite never loaded them.',
      'These are **not** counted as covered.',
      '',
    );
    for (const file of result.unmeasured.keys()) lines.push(`- \`${file}\``);
  }

  return `${lines.join('\n')}\n`;
}

/** `[1,2,3,7,9,10]` -> `1-3, 7, 9-10`. */
export function formatLineRanges(lines: readonly number[]): string {
  const ranges: string[] = [];
  let start: number | undefined;
  let previous: number | undefined;

  const flush = () => {
    if (start === undefined || previous === undefined) return;
    ranges.push(start === previous ? String(start) : `${String(start)}-${String(previous)}`);
  };

  for (const line of lines) {
    if (start === undefined || previous === undefined) {
      start = line;
    } else if (line !== previous + 1) {
      flush();
      start = line;
    }
    previous = line;
  }
  flush();

  return ranges.join(', ');
}

/** Default floor for the covered fraction of changed lines. */
export const DEFAULT_FLOOR = 80;

/**
 * Below this many eligible lines the percentage is reported but not enforced —
 * see GateOptions.minimumLines. A one-line fix cannot be asked for 80%.
 */
export const DEFAULT_MINIMUM_LINES = 25;

/**
 * A `--name value` or `--name=value` flag, looked up in an argv array.
 *
 * Both forms are supported because both are typed, and the two off-by-ones live
 * here rather than in the value parsing: `--name` as the LAST argv entry has no
 * value after it (hence the bounds check), and the inline form's value starts
 * after `--`, the name and `=` — `name.length + 3` characters in.
 */
export function findFlag(name: string, argv: readonly string[]): string | undefined {
  const index = argv.indexOf(`--${name}`);
  if (index !== -1 && index + 1 < argv.length) return argv[index + 1];
  const inline = argv.find((a) => a.startsWith(`--${name}=`));
  return inline?.slice(name.length + 3);
}

/**
 * A numeric flag resolved straight from argv. `null` means SUPPLIED and
 * unreadable — see parseNumericFlag for why that is not a fallback.
 */
export function resolveNumericFlag(
  name: string,
  argv: readonly string[],
  fallback: number,
): number | null {
  return parseNumericFlag(findFlag(name, argv), fallback);
}

/** An absolute path as a repo-relative POSIX path, whatever the host separator. */
export function toRepoRelative(absolute: string, root: string): string {
  return relative(root, absolute).split(sep).join('/');
}

/**
 * The manifest paths in `git ls-files` output, minus vendored ones.
 *
 * Derived from the manifests rather than globbed, so a package whose suite did
 * not run is reported as a MISSING report rather than silently skipped — the
 * difference between "nothing changed there" and "nothing measured it".
 */
export function parseManifestList(lsFiles: string): string[] {
  return lsFiles.split('\n').filter((f) => f && !f.includes('node_modules'));
}

/** Which packages reported coverage, and which owe a report. */
export interface ReportSelection {
  /** Absolute paths to each `coverage-final.json` that exists. */
  readonly reports: string[];
  /** Repo-relative paths to each report a test-running package did not write. */
  readonly missing: string[];
}

/** The seams `selectCoverageReports` needs — a JSON reader and an existence test. */
export interface ReportLookup {
  readonly root: string;
  readFile(path: string): string;
  exists(path: string): boolean;
}

/**
 * Split the packages that declare a `test` script into those that wrote a
 * coverage report and those that did not.
 *
 * `missing` is kept separate rather than folded into an empty list because the
 * caller must be able to tell "a package did not report" from "no package runs
 * tests" — the first is fatal, the second is not.
 */
export function selectCoverageReports(
  manifests: readonly string[],
  lookup: ReportLookup,
): ReportSelection {
  const reports: string[] = [];
  const missing: string[] = [];

  for (const manifest of manifests) {
    const pkg = JSON.parse(lookup.readFile(resolve(lookup.root, manifest))) as {
      scripts?: Record<string, string>;
    };
    if (!pkg.scripts?.test) continue;
    const report = resolve(lookup.root, manifest, '..', 'coverage', 'coverage-final.json');
    if (lookup.exists(report)) reports.push(report);
    else missing.push(toRepoRelative(report, lookup.root));
  }

  return { reports, missing };
}

/**
 * Everything the gate needs from the outside world. The CLI entry supplies the
 * real implementations; a test supplies canned ones, which is what makes every
 * branch below reachable without a git repository or a filesystem.
 */
export interface GateIo extends ReportLookup {
  readonly argv: readonly string[];
  git(args: readonly string[]): string;
  writeOut(text: string): void;
  writeErr(text: string): void;
  appendSummary(file: string, text: string): void;
}

/**
 * Run the gate and return the process exit code: 0 clear, 1 below the floor or
 * a broken environment, 2 a flag that was supplied and could not be read.
 */
export function runGate(io: GateIo): number {
  const base = findFlag('base', io.argv) ?? 'origin/main';

  const numeric = (name: string, fallback: number): number | null => {
    const value = resolveNumericFlag(name, io.argv, fallback);
    if (value === null) {
      io.writeErr(
        `coverage-gate: --${name} must be a non-negative number, ` +
          `got "${String(findFlag(name, io.argv))}".\n`,
      );
    }
    return value;
  };

  const floor = numeric('floor', DEFAULT_FLOOR);
  if (floor === null) return 2;
  const minimumLines = numeric('minimum-lines', DEFAULT_MINIMUM_LINES);
  if (minimumLines === null) return 2;
  const summaryFile = findFlag('summary', io.argv);

  let selection: ReportSelection;
  try {
    selection = selectCoverageReports(
      parseManifestList(io.git(['ls-files', '*/package.json', '*/*/package.json'])),
      io,
    );
  } catch (error) {
    // git absent, or not a work tree. Without this the failure surfaces as a
    // raw execFileSync stack trace naming node:child_process, which points at
    // this tool rather than at the environment that actually broke.
    io.writeErr(`coverage-gate: cannot enumerate packages: ${String(error)}\n`);
    return 1;
  }

  if (selection.missing.length > 0) {
    // Loud, and fatal. A gate that quietly measures some of the packages and
    // stays silent about the rest reports a number that looks like coverage and
    // is not one: every changed file in a package whose report is absent lands
    // in `unmeasured`, which reads as "excluded on purpose".
    io.writeErr('coverage-gate: no coverage report for:\n');
    for (const path of selection.missing) io.writeErr(`  ${path}\n`);
    io.writeErr('Run `pnpm turbo run test` first — it is what writes them.\n');
    return 1;
  }

  // `diff` against the merge base, not the base tip: a two-dot diff against a
  // moved base attributes every line that landed on main since the branch
  // started to this PR, so an unrelated merge can redden it — or, with the
  // arithmetic running the other way, dilute a genuinely untested change into a
  // passing percentage.
  let mergeBase: string;
  try {
    mergeBase = io.git(['merge-base', base, 'HEAD']).trim();
  } catch {
    io.writeErr(`coverage-gate: cannot resolve a merge base with "${base}".\n`);
    io.writeErr('Fetch it first (actions/checkout uses depth 1 by default).\n');
    return 1;
  }

  // The prefixes and --no-ext-diff are pinned rather than inherited. A user's
  // `diff.external` replaces this output with another tool's format, and
  // `diff.noprefix` drops the a/ b/ that stripDiffPrefix strips — and BOTH
  // degrade to an unparseable diff, which reads as "no lines changed" and exits
  // 0. A gate whose local configuration can silently switch it off is not one.
  const diff = io.git([
    'diff',
    '--unified=0',
    '--no-color',
    '--no-ext-diff',
    '--src-prefix=a/',
    '--dst-prefix=b/',
    `${mergeBase}...HEAD`,
  ]);
  const added = parseUnifiedDiff(diff);

  const indexes: CoverageIndex[] = selection.reports.map((report) =>
    indexIstanbulReport(
      JSON.parse(io.readFile(report)) as Record<string, IstanbulFileCoverage>,
      (absolute) => toRepoRelative(absolute, io.root),
    ),
  );

  const result = diffCoverage(added, mergeCoverageIndexes(indexes));
  const verdict = evaluateGate(result, { floor, minimumLines });
  const report = formatReport(result, verdict);

  io.writeOut(report);
  if (summaryFile !== undefined) io.appendSummary(summaryFile, report);
  return verdict.passed ? 0 : 1;
}
