#!/usr/bin/env node
// CI gate over `pnpm audit`: fails when the lockfile carries a high or
// critical advisory without an unexpired waiver in .github/audit-waivers.json.
// Lower severities never block; they appear in the report only. The audit
// works from the lockfile alone, so no `pnpm install` is required first.
//
// Always writes audit-report.md at the repository root — the workflow appends
// it to the run summary, and the scheduled run posts it to the
// advisory-tracking issue. The waiver format and process are documented in
// CONTRIBUTING.md ("Dependency advisories and waivers").
//
// Exit codes:
//   0 — no blocking advisories (clean, or every hit waived)
//   1 — at least one unwaived high/critical advisory
//   2 — the audit could not be completed (transient; retried, then fails closed)
//   3 — invalid gate configuration (waiver file, or pnpm.auditConfig mutes) —
//       deterministic, not worth retrying

import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  assertNothingMuted,
  type AuditPayload,
  buildReport,
  classify,
  parseAuditPayload,
  validateWaivers,
  type Waiver,
  WaiverConfigError,
} from './lib.ts';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const WAIVERS_PATH = join(REPO_ROOT, '.github', 'audit-waivers.json');
const REPORT_PATH = join(REPO_ROOT, 'audit-report.md');

const errorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

const print = (line: string): void => {
  process.stdout.write(`${line}\n`);
};

// Synchronous sleep between retries; Node permits Atomics.wait on the main thread.
function sleepMs(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// The npm audit endpoint is a separate — and historically flakier — service
// from the tarball CDN, and this runs as a required check: a single transport
// blip should not block every merge. Three attempts, then fail closed.
function runAudit(): AuditPayload {
  let lastError: unknown;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const result = spawnSync('pnpm', ['audit', '--json'], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
        // On Windows pnpm is a .cmd shim, which spawnSync only resolves
        // through a shell.
        shell: process.platform === 'win32',
      });
      if (result.error) {
        throw new Error(`could not spawn pnpm: ${result.error.message}`);
      }
      return parseAuditPayload(result.stdout, result.stderr);
    } catch (error) {
      lastError = error;
      if (attempt < 3) sleepMs(attempt * 2000);
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

function failReport(message: string, exitCode: number): void {
  writeFileSync(
    REPORT_PATH,
    `# Dependency audit\n\n**Audit could not be completed.** ${message}\n`,
  );
  print(`::error::dependency audit could not be completed: ${message}`);
  process.exitCode = exitCode;
}

function main(): void {
  let waivers: Waiver[];
  try {
    waivers = validateWaivers(JSON.parse(readFileSync(WAIVERS_PATH, 'utf8')));
  } catch (error) {
    failReport(`invalid waiver config: ${errorMessage(error)}`, 3);
    return;
  }

  let payload: AuditPayload;
  try {
    payload = runAudit();
    assertNothingMuted(payload);
  } catch (error) {
    failReport(errorMessage(error), error instanceof WaiverConfigError ? 3 : 2);
    return;
  }

  const today = new Date().toISOString().slice(0, 10);
  const classification = classify(payload, waivers, today);
  const { blocking, waived, nonBlocking, stale } = classification;

  const counts = payload.metadata?.vulnerabilities ?? {};
  writeFileSync(REPORT_PATH, buildReport({ counts, ...classification }) + '\n');

  for (const advisory of blocking) {
    const id = advisory.github_advisory_id ?? String(advisory.id ?? '');
    print(
      `::error::${advisory.severity ?? ''} advisory ${id} in ${advisory.module_name ?? ''} — ${advisory.title ?? ''} (${advisory.url ?? ''})`,
    );
  }
  for (const { waiver, why } of stale) {
    print(`::notice::stale audit waiver ${waiver.advisory} — ${why}`);
  }

  if (blocking.length > 0) {
    print(
      `Dependency audit failed: ${String(blocking.length)} blocking advisor${blocking.length === 1 ? 'y' : 'ies'} (see audit-report.md).`,
    );
    process.exitCode = 1;
    return;
  }
  print(
    `Dependency audit passed: ${String(waived.length)} waived, ${String(nonBlocking.length)} below the gate.`,
  );
}

main();
