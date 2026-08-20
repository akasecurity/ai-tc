#!/usr/bin/env node
// Reads which status checks branch protection actually requires on `main`, and
// compares that against the Enforced column of CONTRIBUTING.md's gate table.
//
// Why a job rather than a note. The required set lives in repository settings,
// so nothing in this tree can set it and no test can read it at build time. It
// is also matched by NAME — rename a job and protection waits for a name
// nothing emits, so the check stops gating with nothing in any diff to review.
// A hand-recorded "measured on <date>" line cannot catch that; this can.
//
// Why `isRequired`. Three endpoints mislead a non-admin: the branch-protection
// REST endpoint 404s (which reads exactly like no protection at all), GraphQL's
// `branchProtectionRules` returns an empty list, and `rulesets` is genuinely
// empty because the protection in use is the older classic kind. Only
// `StatusCheckRollupContext.isRequired(pullRequestNumber:)` answers, and it
// answers at ordinary read permission — which is what makes this job runnable
// without handing it an admin token.
//
// Every decision lives in lib.ts, where the suite drives it. What is here is
// the `gh` spawn, two file operations and the exit-code mapping.
//
// Exit codes:
//   0 — the live set matches the Enforced column (outstanding ⛔ rows are fine)
//   1 — drift: a check stopped being required, one started, one is required
//       and untabled, or one recorded as enforced was not reported at all
//   2 — the state could not be read (no usable PR, `gh` failed)
//   3 — invalid gate configuration (the table is missing or malformed)

import { spawnSync } from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { type GateIo, runGate } from './lib.ts';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
// Owner and repo from the runner rather than baked in: a fork with Actions
// enabled runs this schedule too, and a hardcoded slug there reads the UPSTREAM
// repository's pull requests and compares their required set against the fork's
// own CONTRIBUTING.md — reporting drift the fork can neither cause nor fix.
function ownerRepo(): [string, string] {
  // eslint-disable-next-line n/no-process-env -- GITHUB_REPOSITORY is the runner's own identity
  const slug = process.env.GITHUB_REPOSITORY ?? '';
  const [owner, repo] = slug.split('/');
  return owner !== undefined && owner !== '' && repo !== undefined && repo !== ''
    ? [owner, repo]
    : ['akasecurity', 'ai-tc'];
}

const [OWNER, REPO] = ownerRepo();

// How many recent pull requests to consider. Only one is read — the newest that
// reported any checks — but a PR can exist with an empty rollup, and reading
// that one would report every check as unreported. Widening this costs payload
// on the FIRST of the two queries below, not a third round trip: that query
// asks only for each candidate's check COUNT, so a larger window is cheap
// without being free.
const PR_CANDIDATES = 10;

// The step-summary path is a runner variable, absent when run locally — where
// stdout is the whole output and appending nowhere is correct.
function summaryFile(): string | undefined {
  // eslint-disable-next-line n/no-process-env -- GITHUB_STEP_SUMMARY is the runner's own output channel
  const path = process.env.GITHUB_STEP_SUMMARY;
  return path === undefined || path === '' ? undefined : path;
}

// Every decision — which exit code, which message — lives in `runGate`, where
// the suite drives it against fakes. What is left here is the four real
// boundaries it needs.
const io: GateIo = {
  readRecord: () => readFileSync(join(REPO_ROOT, 'CONTRIBUTING.md'), 'utf8'),
  graphql: (query) => {
    const result = spawnSync('gh', ['api', 'graphql', '-f', `query=${query}`], {
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
      cwd: REPO_ROOT,
    });
    if (result.error) throw new Error(`could not spawn gh: ${result.error.message}`);
    if (result.status !== 0) {
      throw new Error(
        `gh api graphql failed: ${(result.stderr || result.stdout).trim().slice(0, 400)}`,
      );
    }
    return result.stdout;
  },
  print: (line) => process.stdout.write(`${line}\n`),
  appendSummary: (text) => {
    const path = summaryFile();
    if (path !== undefined) appendFileSync(path, `${text}\n`);
  },
};

process.exitCode = runGate(io, OWNER, REPO, PR_CANDIDATES);
