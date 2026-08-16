#!/usr/bin/env node
/**
 * The CLI entry for the diff-coverage gate. It owns all I/O — running git,
 * reading coverage reports, writing stdout and the step summary — and decides
 * nothing; every decision lives in lib.ts, where the unit suite drives it with
 * canned argv, canned git output and a canned filesystem.
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
import { resolve } from 'node:path';

import { type GateIo, runGate } from './lib.ts';

const REPO_ROOT = resolve(import.meta.dirname, '..', '..', '..');

const io: GateIo = {
  argv: process.argv,
  root: REPO_ROOT,
  git: (args) =>
    execFileSync('git', [...args], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
    }),
  readFile: (path) => readFileSync(path, 'utf8'),
  exists: (path) => existsSync(path),
  writeOut: (text) => {
    process.stdout.write(text);
  },
  writeErr: (text) => {
    process.stderr.write(text);
  },
  appendSummary: (file, text) => {
    appendFileSync(file, text);
  },
};

process.exitCode = runGate(io);
