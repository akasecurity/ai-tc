#!/usr/bin/env node
// CI gate over the dependency audits: fails when an audit carries a high or
// critical advisory without an unexpired waiver in .github/audit-waivers.json.
// Lower severities never block; they appear in the report only. Two modes:
//
//   (default)    `pnpm audit` over the workspace lockfile. Works from the
//                lockfile alone, so no `pnpm install` is required first.
//   --artifact   `npm audit` over the resolution an end user gets from
//                `npm install @akasecurity/cli`. Consumers re-resolve the
//                published runtime ranges (e.g. next's own pins), which the
//                workspace lockfile and `pnpm.overrides` never reach: this
//                mode writes cli/package.json's runtime "dependencies" to a
//                temp manifest, resolves it with
//                `npm install --package-lock-only`, and audits that lockfile.
//
// Each mode writes its report at the repository root (audit-report.md /
// artifact-audit-report.md) — the workflow appends them to the run summary,
// and the scheduled run posts them to the advisory-tracking issue. The waiver
// format and process are documented in CONTRIBUTING.md ("Dependency
// advisories and waivers"); every waiver names the mode it applies to via
// "scope", so a waiver held for one audit is never flagged stale by the other.
//
// Exit codes:
//   0 — no blocking advisories (clean, or every hit waived)
//   1 — at least one unwaived high/critical advisory
//   2 — the audit could not be completed (transient; retried, then fails closed)
//   3 — invalid gate configuration (waiver file, pnpm.auditConfig mutes, or an
//       unauditable cli manifest) — deterministic, not worth retrying

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  assertNoAuditConfigMutes,
  assertNothingMuted,
  type AuditMode,
  type AuditPayload,
  buildReport,
  classify,
  normalizeNpmAudit,
  parseAuditPayload,
  parseNpmAuditPayload,
  REPORT_STYLES,
  validateWaivers,
  type Waiver,
  WaiverConfigError,
  waiversFor,
} from './lib.ts';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const WAIVERS_PATH = join(REPO_ROOT, '.github', 'audit-waivers.json');
const CLI_MANIFEST_PATH = join(REPO_ROOT, 'cli', 'package.json');
const ROOT_MANIFEST_PATH = join(REPO_ROOT, 'package.json');
const WORKSPACE_YAML_PATH = join(REPO_ROOT, 'pnpm-workspace.yaml');
const REPORT_PATHS: Record<AuditMode, string> = {
  workspace: join(REPO_ROOT, 'audit-report.md'),
  artifact: join(REPO_ROOT, 'artifact-audit-report.md'),
};

const SPAWN_OPTIONS = {
  encoding: 'utf8',
  maxBuffer: 64 * 1024 * 1024,
  // On Windows pnpm and npm are .cmd shims, which spawnSync only resolves
  // through a shell.
  shell: process.platform === 'win32',
} as const;

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
// blip should not block every merge. Three attempts, then fail closed. A
// WaiverConfigError is deterministic and rethrown without retrying.
function withRetries<T>(attemptFn: () => T): T {
  let lastError: unknown;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      return attemptFn();
    } catch (error) {
      if (error instanceof WaiverConfigError) throw error;
      lastError = error;
      if (attempt < 3) sleepMs(attempt * 2000);
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

// Absent is not an error: only a file that exists is inspected, so a checkout
// without a workspace manifest simply contributes nothing to look at. Absent
// means ENOENT and nothing else — a file that exists but cannot be read is
// refused rather than reported as "no config here", which is how the JSON
// parse failure in findAuditConfigMutes already behaves. Reading a mute as
// absence is the one outcome this check exists to prevent, so it must not be
// reachable through a failed read either.
const readIfPresent = (path: string): string | undefined => {
  try {
    return readFileSync(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw new WaiverConfigError(
      `${basename(path)} exists but could not be read (${errorMessage(error)}), so its pnpm config is unknown`,
    );
  }
};

function runWorkspaceAudit(): AuditPayload {
  // Before spawning anything: a pnpm-side mute would leave the payload looking
  // clean, so this has to be read off disk rather than detected in the result.
  assertNoAuditConfigMutes({
    manifest: readIfPresent(ROOT_MANIFEST_PATH),
    workspaceYaml: readIfPresent(WORKSPACE_YAML_PATH),
  });
  return withRetries(() => {
    const result = spawnSync('pnpm', ['audit', '--json'], { ...SPAWN_OPTIONS, cwd: REPO_ROOT });
    if (result.error) {
      throw new Error(`could not spawn pnpm: ${result.error.message}`);
    }
    const payload = parseAuditPayload(result.stdout, result.stderr);
    assertNothingMuted(payload);
    return payload;
  });
}

function loadCliRuntimeDependencies(): Record<string, string> {
  let manifest: unknown;
  try {
    manifest = JSON.parse(readFileSync(CLI_MANIFEST_PATH, 'utf8'));
  } catch (error) {
    throw new WaiverConfigError(`cannot read cli/package.json: ${errorMessage(error)}`);
  }
  const dependencies = (manifest as { dependencies?: unknown } | null)?.dependencies;
  if (
    dependencies === null ||
    typeof dependencies !== 'object' ||
    Object.keys(dependencies).length === 0
  ) {
    throw new WaiverConfigError('cli/package.json has no runtime "dependencies" to audit');
  }
  return dependencies as Record<string, string>;
}

function runArtifactAudit(): AuditPayload {
  const dependencies = loadCliRuntimeDependencies();
  return withRetries(() => {
    const dir = mkdtempSync(join(tmpdir(), 'artifact-audit-'));
    try {
      writeFileSync(
        join(dir, 'package.json'),
        JSON.stringify(
          { name: 'artifact-audit', version: '0.0.0', private: true, dependencies },
          null,
          2,
        ) + '\n',
      );
      const install = spawnSync(
        'npm',
        ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'],
        { ...SPAWN_OPTIONS, cwd: dir },
      );
      if (install.error) {
        throw new Error(`could not spawn npm: ${install.error.message}`);
      }
      if (install.status !== 0) {
        const detail = (install.stderr || install.stdout || '').trim().slice(0, 400);
        throw new Error(`npm could not resolve the artifact dependency tree: ${detail}`);
      }
      const result = spawnSync('npm', ['audit', '--json'], { ...SPAWN_OPTIONS, cwd: dir });
      if (result.error) {
        throw new Error(`could not spawn npm: ${result.error.message}`);
      }
      return normalizeNpmAudit(parseNpmAuditPayload(result.stdout, result.stderr));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

function failReport(mode: AuditMode, message: string, exitCode: number): void {
  writeFileSync(
    REPORT_PATHS[mode],
    `# ${REPORT_STYLES[mode].title}\n\n**Audit could not be completed.** ${message}\n`,
  );
  print(`::error::${mode} dependency audit could not be completed: ${message}`);
  process.exitCode = exitCode;
}

function main(): void {
  const mode: AuditMode = process.argv.includes('--artifact') ? 'artifact' : 'workspace';
  const reportPath = REPORT_PATHS[mode];

  let waivers: Waiver[];
  try {
    waivers = validateWaivers(JSON.parse(readFileSync(WAIVERS_PATH, 'utf8')));
  } catch (error) {
    failReport(mode, `invalid waiver config: ${errorMessage(error)}`, 3);
    return;
  }

  let payload: AuditPayload;
  try {
    payload = mode === 'artifact' ? runArtifactAudit() : runWorkspaceAudit();
  } catch (error) {
    failReport(mode, errorMessage(error), error instanceof WaiverConfigError ? 3 : 2);
    return;
  }

  const today = new Date().toISOString().slice(0, 10);
  const classification = classify(payload, waiversFor(mode, waivers), today);
  const { blocking, waived, nonBlocking, stale } = classification;

  const counts = payload.metadata?.vulnerabilities ?? {};
  writeFileSync(reportPath, buildReport({ mode, counts, ...classification }) + '\n');

  for (const advisory of blocking) {
    const id = advisory.github_advisory_id ?? String(advisory.id ?? '');
    print(
      `::error::[${mode}] ${advisory.severity ?? ''} advisory ${id} in ${advisory.module_name ?? ''} — ${advisory.title ?? ''} (${advisory.url ?? ''})`,
    );
  }
  for (const { waiver, why } of stale) {
    print(`::notice::stale ${mode} audit waiver ${waiver.advisory} — ${why}`);
  }

  if (blocking.length > 0) {
    print(
      `Dependency audit (${mode}) failed: ${String(blocking.length)} blocking advisor${blocking.length === 1 ? 'y' : 'ies'} (see ${basename(reportPath)}).`,
    );
    process.exitCode = 1;
    return;
  }
  print(
    `Dependency audit (${mode}) passed: ${String(waived.length)} waived, ${String(nonBlocking.length)} below the gate.`,
  );
}

main();
