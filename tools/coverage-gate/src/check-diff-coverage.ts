#!/usr/bin/env node
/**
 * The I/O half of the diff-coverage gate: collect every package's
 * `coverage-final.json`, take the diff against a base ref, and report what
 * fraction of the changed lines the suite executed.
 *
 * Run after `turbo run test`, which is what produces the reports.
 *
 *   node tools/coverage-gate/src/check-diff-coverage.ts [--base <ref>]
 *                                                       [--floor <percent>]
 *                                                       [--summary <file>]
 *
 * There is deliberately no aggregate/global coverage threshold here or
 * anywhere else. Per-package floors live in test/vitest/coverage.ts and are
 * enforced by each package's own vitest run; this gate answers the other
 * question — whether the code THIS change adds is tested — and a repo-wide
 * percentage answers neither.
 */
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';

import {
  type CoverageIndex,
  diffCoverage,
  evaluateGate,
  formatReport,
  indexIstanbulReport,
  type IstanbulFileCoverage,
  mergeCoverageIndexes,
  parseNumericFlag,
  parseUnifiedDiff,
} from './lib.ts';

const REPO_ROOT = resolve(import.meta.dirname, '..', '..', '..');

/** Default floor for the covered fraction of changed lines. */
const DEFAULT_FLOOR = 80;

/**
 * Below this many eligible lines the percentage is reported but not enforced —
 * see GateOptions.minimumLines. A one-line fix cannot be asked for 80%.
 */
const DEFAULT_MINIMUM_LINES = 25;

const git = (args: readonly string[]): string =>
  execFileSync('git', [...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  });

/** A numeric flag, refused rather than coerced — see parseNumericFlag. */
function numericArg(name: string, fallback: number): number {
  const raw = arg(name);
  const value = parseNumericFlag(raw, fallback);
  if (value === null) {
    process.stderr.write(
      `coverage-gate: --${name} must be a non-negative number, got "${String(raw)}".\n`,
    );
    process.exit(2);
  }
  return value;
}

const arg = (name: string): string | undefined => {
  const index = process.argv.indexOf(`--${name}`);
  if (index !== -1 && index + 1 < process.argv.length) return process.argv[index + 1];
  const inline = process.argv.find((a) => a.startsWith(`--${name}=`));
  return inline?.slice(name.length + 3);
};

const toRepoRelative = (absolute: string): string =>
  relative(REPO_ROOT, absolute).split(sep).join('/');

/**
 * Every `coverage/coverage-final.json` a package wrote.
 *
 * Returns the reports, or `undefined` when any is missing — a distinct answer
 * from an empty list, so the caller cannot confuse "a package did not report"
 * with "no package runs tests".
 */
function coverageReports(): string[] | undefined {
  // Derived from the manifests rather than globbed, so a package whose suite
  // did not run is reported as a MISSING report rather than silently skipped —
  // the difference between "nothing changed there" and "nothing measured it".
  const manifests = git(['ls-files', '*/package.json', '*/*/package.json'])
    .split('\n')
    .filter((f) => f && !f.includes('node_modules'));

  const reports: string[] = [];
  const missing: string[] = [];
  for (const manifest of manifests) {
    const pkg = JSON.parse(readFileSync(resolve(REPO_ROOT, manifest), 'utf8')) as {
      scripts?: Record<string, string>;
    };
    if (!pkg.scripts?.test) continue;
    const report = resolve(REPO_ROOT, manifest, '..', 'coverage', 'coverage-final.json');
    if (existsSync(report)) reports.push(report);
    else missing.push(toRepoRelative(report));
  }

  if (missing.length > 0) {
    // Loud, and fatal. A gate that quietly measures 12 of 21 packages reports a
    // number that looks like coverage and is not one: every changed file in a
    // package whose report is absent lands in `unmeasured`, which reads as
    // "excluded on purpose".
    process.stderr.write('coverage-gate: no coverage report for:\n');
    for (const path of missing) process.stderr.write(`  ${path}\n`);
    process.stderr.write('Run `pnpm turbo run test` first — it is what writes them.\n');
    return undefined;
  }
  return reports;
}

function main(): void {
  const base = arg('base') ?? 'origin/main';
  const floor = numericArg('floor', DEFAULT_FLOOR);
  const minimumLines = numericArg('minimum-lines', DEFAULT_MINIMUM_LINES);
  const summaryFile = arg('summary');

  let reports: string[] | undefined;
  try {
    reports = coverageReports();
  } catch (error) {
    // git absent, or not a work tree. Without this the failure surfaces as a
    // raw execFileSync stack trace naming node:child_process, which points at
    // this tool rather than at the environment that actually broke.
    process.stderr.write(`coverage-gate: cannot enumerate packages: ${String(error)}\n`);
    process.exitCode = 1;
    return;
  }
  if (reports === undefined) {
    process.exitCode = 1;
    return;
  }

  // `diff` against the merge base, not the base tip: a two-dot diff against a
  // moved base attributes every line that landed on main since the branch
  // started to this PR, so an unrelated merge can redden it — or, with the
  // arithmetic running the other way, dilute a genuinely untested change into a
  // passing percentage.
  let mergeBase: string;
  try {
    mergeBase = git(['merge-base', base, 'HEAD']).trim();
  } catch {
    process.stderr.write(`coverage-gate: cannot resolve a merge base with "${base}".\n`);
    process.stderr.write('Fetch it first (actions/checkout uses depth 1 by default).\n');
    process.exitCode = 1;
    return;
  }

  // The prefixes and --no-ext-diff are pinned rather than inherited. A user's
  // `diff.external` replaces this output with another tool's format, and
  // `diff.noprefix` drops the a/ b/ that stripDiffPrefix strips — and BOTH
  // degrade to an unparseable diff, which reads as "no lines changed" and exits
  // 0. A gate whose local configuration can silently switch it off is not one.
  const diff = git([
    'diff',
    '--unified=0',
    '--no-color',
    '--no-ext-diff',
    '--src-prefix=a/',
    '--dst-prefix=b/',
    `${mergeBase}...HEAD`,
  ]);
  const added = parseUnifiedDiff(diff);

  const indexes: CoverageIndex[] = reports.map((report) =>
    indexIstanbulReport(
      JSON.parse(readFileSync(report, 'utf8')) as Record<string, IstanbulFileCoverage>,
      toRepoRelative,
    ),
  );

  const result = diffCoverage(added, mergeCoverageIndexes(indexes));
  const verdict = evaluateGate(result, { floor, minimumLines });
  const report = formatReport(result, verdict);

  process.stdout.write(report);
  if (summaryFile !== undefined) appendFileSync(summaryFile, report);
  if (!verdict.passed) process.exitCode = 1;
}

main();
