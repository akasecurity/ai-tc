#!/usr/bin/env node
// CI gate: shipped source, docs, workflows, and prose must not carry internal
// narration — design-doc/section citations, PR/phase delivery notes, or editing
// artifacts. Comments explain WHAT the code does, never the decision history
// behind it. Any hit fails the check (exit 1).
//
// Sanctioned hits are waived through ALLOW below; each entry is scoped to one
// file and one pattern (plus an optional line substring) — never a whole class
// of files. Add an entry only with a justification comment.
//
// Extra deployment-local patterns are read from
// scripts/comment-hygiene.local.json when that (optional, untracked) file is
// present. Shape: [{ "pattern": "...", "flags": "i", "what": "..." }].
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, sep } from 'node:path';

// Everything that ships: published/bundled source, docs, rule packs, CI
// workflows, contributor guides, and the repo-level markdown.
const ROOTS = [
  '.github',
  'cli',
  'docs',
  'packages',
  'plugins',
  'rules',
  'scripts',
  'skills',
  'tools',
  'web-ui',
  'CLAUDE.md',
  'CODE_OF_CONDUCT.md',
  'CONTRIBUTING.md',
  'README.md',
  'SECURITY.md',
];

// Unambiguous internal-narration patterns (kept narrow to avoid false positives
// on legitimate architecture prose). Deployment-local additions come from
// scripts/comment-hygiene.local.json — never inline sensitive strings here.
const FORBIDDEN = [
  { re: /§\s?\d/, what: 'internal design-doc section reference' },
  { re: /§[A-Z]\d/, what: 'internal design-doc lettered-section reference' },
  { re: /\b(?:HLD|LLD)\b/, what: 'internal design-doc reference (HLD/LLD)' },
  { re: /technical[- ]plan/i, what: 'internal planning-doc citation' },
  { re: /\bADR-\d/, what: 'internal ADR reference' },
  // Uppercase only: lowercase would false-positive on Tailwind pr-N padding
  // classes. The optional trailing letter catches digit+letter sub-part citations.
  { re: /\bPR\s?#?-?\d+[a-z]?\b/, what: 'internal PR-number reference' },
  { re: /\b(?:this|a later|an earlier) PR\b/i, what: 'PR-staging narration' },
  { re: /\bPhase[ -]?\d+\b/i, what: 'internal phase-roadmap reference' },
  { re: /\bPhase[ -][A-Z]\b/, what: 'internal phase-roadmap reference (lettered)' },
  { re: /\bpre-split\b/i, what: 'repo-history narration' },
  { re: /secret sauce/i, what: 'internal "secret sauce" phrasing' },
  { re: /TODO\s?\(week/i, what: 'sprint-scheduling narration' },
  { re: /\bfield bug\b/i, what: 'internal incident reference' },
  { re: /\.api\.md\b/, what: 'reference to a non-shipped API design doc' },
  { re: /<\/(?:content|invoke)>|\bantml\b/, what: 'AI-editing artifact' },
];

// Sanctioned hits. Scope: exact file + exact pattern label (+ optional
// substring the flagged line must contain). Keep this list short.
const ALLOW = [
  // This gate's own pattern definitions legitimately spell the generic phrases
  // they ban (matched per pattern label, so any other hit here still fails).
  { file: 'scripts/check-comment-hygiene.mjs', what: 'internal design-doc reference (HLD/LLD)' },
  { file: 'scripts/check-comment-hygiene.mjs', what: 'repo-history narration' },
  { file: 'scripts/check-comment-hygiene.mjs', what: 'internal "secret sauce" phrasing' },
  { file: 'scripts/check-comment-hygiene.mjs', what: 'internal incident reference' },
  // Contributor-facing template prose about the reader's own pull request.
  {
    file: '.github/PULL_REQUEST_TEMPLATE.md',
    what: 'PR-staging narration',
    lineIncludes: 'Keep the PR focused on one thing',
  },
  // Public SemVer spec citation (precedence clause), not an internal doc.
  {
    file: 'packages/local-ops/src/semver.ts',
    what: 'internal design-doc section reference',
    lineIncludes: 'per semver',
  },
  {
    file: 'packages/persistence/src/semver.ts',
    what: 'internal design-doc section reference',
    lineIncludes: 'per semver',
  },
  {
    file: 'packages/persistence/src/semver.test.ts',
    what: 'internal design-doc section reference',
    lineIncludes: '(semver',
  },
];

const LOCAL_PATTERNS = 'scripts/comment-hygiene.local.json';

// Build/dependency output is never scanned, wherever it appears.
const SKIP_DIR_NAMES = new Set([
  'node_modules',
  'dist',
  'build',
  'coverage',
  'generated',
  '.git',
  '.next',
  '.turbo',
  '.venv',
  '__pycache__',
]);
// Gitignored artifacts that live under otherwise-scanned roots.
const SKIP_PATHS = new Set(['docs/site', 'plugins/claude-code/scripts']);
const SKIP_FILES = /(?:\/generated\/|\.generated\.|\.openapi\.json$|comment-hygiene\.local\.json$)/;
const SOURCE = /\.(?:ts|tsx|mts|cts|js|mjs|cjs|md|yml|yaml|sh|ps1)$/;

let localPatternCount = 0;
try {
  const entries = JSON.parse(readFileSync(LOCAL_PATTERNS, 'utf8'));
  if (!Array.isArray(entries)) throw new Error('expected a top-level array');
  for (const entry of entries) {
    if (typeof entry?.pattern !== 'string' || typeof entry?.what !== 'string') {
      throw new Error('each entry needs string "pattern" and "what" fields');
    }
    FORBIDDEN.push({ re: new RegExp(entry.pattern, entry.flags ?? ''), what: entry.what });
    localPatternCount += 1;
  }
} catch (err) {
  if (err?.code !== 'ENOENT') {
    process.stderr.write(
      `comment-hygiene: failed to load ${LOCAL_PATTERNS}: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
}

const toPosix = (p) => p.split(sep).join('/');

function* walk(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    const posix = toPosix(p);
    if (SKIP_PATHS.has(posix)) continue;
    if (e.isDirectory()) {
      if (!SKIP_DIR_NAMES.has(e.name)) yield* walk(p);
    } else if (SOURCE.test(e.name) && !SKIP_FILES.test(posix)) {
      yield posix;
    }
  }
}

function* files() {
  for (const root of ROOTS) {
    if (statSync(root).isFile()) yield toPosix(root);
    else yield* walk(root);
  }
}

const missing = ROOTS.filter((r) => {
  try {
    statSync(r);
    return false;
  } catch {
    return true;
  }
});
if (missing.length > 0) {
  process.stderr.write(
    `comment-hygiene misconfigured — missing root(s):\n${missing.map((m) => `  ${m}`).join('\n')}\n`,
  );
  process.exit(1);
}

const isAllowed = (file, what, line) =>
  ALLOW.some(
    (a) =>
      a.file === file &&
      a.what === what &&
      (a.lineIncludes === undefined || line.includes(a.lineIncludes)),
  );

const violations = [];
for (const file of files()) {
  readFileSync(file, 'utf8')
    .split('\n')
    .forEach((line, i) => {
      for (const { re, what } of FORBIDDEN) {
        if (re.test(line) && !isAllowed(file, what, line)) {
          violations.push(`${file}:${String(i + 1)} — ${what}`);
        }
      }
    });
}

if (violations.length > 0) {
  process.stderr.write('Comment-hygiene violation — internal narration must not ship:\n');
  for (const v of violations) process.stderr.write(`  ${v}\n`);
  process.stderr.write(
    '\nComments describe WHAT the code does; keep decision history out of shipped files.\n',
  );
  process.exit(1);
}
process.stdout.write(
  `Comment-hygiene check passed (${String(ROOTS.length)} roots scanned${
    localPatternCount > 0 ? `, ${String(localPatternCount)} local patterns` : ''
  }).\n`,
);
