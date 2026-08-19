#!/usr/bin/env node
// Local pre-push / lint gate for six cross-platform test bugs: a hardcoded
// file:/// URL, a bare GNU `timeout` inside a shell command string, a path
// comparison with no case normalization, a worker/concurrency test with no
// explicit timeout, a PATH joined on a literal ':', and a platform guard that
// ends a test body with a bare `return`. Scans the git-tracked test tree only —
// see lib.ts's header for what each rule can and cannot see.
//
// Exit codes:
//   0 — no violations
//   1 — at least one violation (see stdout for file:line and rule)

import { spawnSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { formatReport, isRelevantPath, type ScannedFile, scanTree } from './lib.ts';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));

function trackedFiles(): string[] {
  const result = spawnSync('git', ['ls-files'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    // On Windows git is a .cmd/.exe resolved via PATH; spawnSync only
    // resolves shims like this through a shell.
    shell: process.platform === 'win32',
  });
  if (result.error) {
    throw new Error(`could not spawn git: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`git ls-files failed: ${(result.stderr || '').trim()}`);
  }
  return result.stdout.split('\n').filter((line) => line.length > 0);
}

function readScannedFiles(paths: string[]): ScannedFile[] {
  const files: ScannedFile[] = [];
  for (const path of paths) {
    const absolute = join(REPO_ROOT, path);
    // A path git tracks can still be absent from the working tree (a
    // git-tracked symlink pointing nowhere, a submodule placeholder) — skip
    // rather than fail the whole scan over one unreadable entry.
    try {
      if (!statSync(absolute).isFile()) continue;
    } catch {
      continue;
    }
    files.push({ path, content: readFileSync(absolute, 'utf8') });
  }
  return files;
}

function main(): void {
  const paths = trackedFiles().filter(isRelevantPath);
  const files = readScannedFiles(paths);
  const violations = scanTree(files);

  for (const v of violations) {
    process.stdout.write(
      `::error file=${v.file},line=${String(v.line)}::[${v.rule}] ${v.message}\n`,
    );
  }
  process.stdout.write(`${formatReport(violations)}\n`);

  process.exitCode = violations.length > 0 ? 1 : 0;
}

main();
