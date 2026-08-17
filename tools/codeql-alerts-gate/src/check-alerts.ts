#!/usr/bin/env node
// Fails when the number of open CodeQL alerts on `main` moves away from the
// baseline in `.github/codeql-alert-baseline.json`, in either direction.
//
// CodeQL already runs on every PR, every push to main and weekly. What was
// missing is anything that READS the result: findings land in the Security tab
// and accumulate, and the absence of a reader is invisible by construction —
// no run is red and no check is failing while the count climbs.
//
// Every decision lives in lib.ts, where the suite drives it. What is here is
// the `gh` spawn, two file reads and the exit-code mapping.
//
// Exit codes:
//   0 — the open-alert counts match the baseline exactly
//   1 — they moved (up: triage it; down: lower the baseline)
//   2 — the alerts could not be read (`gh` failed, unreadable response)
//   3 — invalid gate configuration (missing or malformed baseline)

import { spawnSync } from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  type Alert,
  AlertGateConfigError,
  buildAlertSummary,
  compareAlerts,
  isAlertFailure,
  parseBaseline,
  summarise,
} from './lib.ts';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const BASELINE_PATH = join(REPO_ROOT, '.github', 'codeql-alert-baseline.json');
// The repository this runs against, from the runner rather than baked in. A
// fork with Actions enabled runs this schedule too, and a hardcoded slug there
// reads the UPSTREAM repository's alerts and compares them to the fork's own
// baseline — a daily failure the fork cannot act on, or a 404 its token earns
// for asking about a repository it has no security-events access to.
function repoSlug(): string {
  // eslint-disable-next-line n/no-process-env -- GITHUB_REPOSITORY is the runner's own identity
  const slug = process.env.GITHUB_REPOSITORY;
  return slug === undefined || slug === '' ? 'akasecurity/ai-tc' : slug;
}

const alertsEndpoint = (): string =>
  `repos/${repoSlug()}/code-scanning/alerts?state=open&per_page=100`;

const print = (line: string): void => {
  process.stdout.write(`${line}\n`);
};

const errorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

// The step-summary path is a runner variable, absent when run locally — where
// stdout is the whole output and appending nowhere is correct.
function summaryFile(): string | undefined {
  // eslint-disable-next-line n/no-process-env -- GITHUB_STEP_SUMMARY is the runner's own output channel
  const path = process.env.GITHUB_STEP_SUMMARY;
  return path === undefined || path === '' ? undefined : path;
}

// `--paginate` matters: the endpoint caps at 100 per page, and a repository
// that crossed that would silently report 100 — a number that can only ever go
// DOWN from there, so the gate would read a growing tree as an improving one.
function fetchAlerts(): Alert[] {
  const result = spawnSync('gh', ['api', '--paginate', alertsEndpoint()], {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    cwd: REPO_ROOT,
  });
  if (result.error) throw new Error(`could not spawn gh: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(`gh api failed: ${(result.stderr || result.stdout).trim().slice(0, 400)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    throw new Error(`gh did not return JSON: ${result.stdout.trim().slice(0, 400)}`);
  }
  // An unreadable shape is refused rather than read as an empty list: empty
  // compares against a non-zero baseline as "every alert was fixed", which
  // reports the good news this gate would otherwise be trusted for.
  if (!Array.isArray(parsed))
    throw new Error('the code-scanning response was not a list of alerts');
  return parsed as Alert[];
}

function main(): void {
  let baseline;
  try {
    baseline = parseBaseline(readFileSync(BASELINE_PATH, 'utf8'));
  } catch (error) {
    print(`::error::${errorMessage(error)}`);
    process.exitCode = error instanceof AlertGateConfigError ? 3 : 2;
    return;
  }

  let alerts: Alert[];
  try {
    alerts = fetchAlerts();
  } catch (error) {
    print(`::error::could not read the open CodeQL alerts: ${errorMessage(error)}`);
    process.exitCode = 2;
    return;
  }

  const summary = summarise(alerts);
  const drift = compareAlerts(baseline, summary);
  const report = buildAlertSummary(drift, summary);

  const summaryPath = summaryFile();
  if (summaryPath !== undefined) appendFileSync(summaryPath, `${report}\n`);
  print(report);

  for (const { severity, was, now } of drift.risen) {
    print(
      `::error::open ${severity} CodeQL alerts rose from ${String(was)} to ${String(now)} — triage them, do not raise the baseline`,
    );
  }
  for (const { severity, was, now } of drift.fallen) {
    print(
      `::error::open ${severity} CodeQL alerts fell from ${String(was)} to ${String(now)} — lower the baseline`,
    );
  }

  if (isAlertFailure(drift)) {
    process.exitCode = 1;
    return;
  }
  print(`Open CodeQL alerts match the baseline: ${String(drift.totalNow)} outstanding.`);
}

main();
