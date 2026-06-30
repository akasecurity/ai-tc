#!/usr/bin/env node
// CI gate: the open-source packages import @akasecurity/* code only from this
// repo's own workspace, keep Drizzle out of everything but the schema
// definitions, and make no network calls (CLAUDE.md "Package dependency
// rules"). This is the explicit, fail-loud check: an import of a
// non-workspace @akasecurity/* package, a Drizzle import outside
// @akasecurity/schema, or any fetch() call anywhere in the shipped surface
// fails CI.
//
// Per-root forbidden lists: @akasecurity/schema legitimately uses Drizzle to
// DEFINE the local-store + registry schemas, so Drizzle is forbidden only in
// the packages that must read the store via node:sqlite (persistence) or stay
// presentation-only (dashboard-ui, web-ui).
//
// The product is local-only — it runs on Node + the SQLite store under ~/.aka
// and talks to no AKA service. The only network access is package-manager
// shell-outs (`npm`/`claude`) in @akasecurity/local-ops, so a direct fetch()
// must never appear.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const SCOPE = '@akasecurity/';
const DRIZZLE = ['drizzle-orm', 'drizzle-kit'];

// Every @akasecurity/* package that exists in this repo. Any other specifier
// under the scope is not part of this codebase and must not be imported.
function workspacePackageNames() {
  const manifestDirs = ['cli', 'web-ui'];
  for (const parent of ['packages', 'plugins', 'tools']) {
    if (!existsSync(parent)) continue;
    for (const entry of readdirSync(parent, { withFileTypes: true })) {
      if (entry.isDirectory()) manifestDirs.push(join(parent, entry.name));
    }
  }
  const names = new Set();
  for (const dir of manifestDirs) {
    const manifest = join(dir, 'package.json');
    if (!existsSync(manifest)) continue;
    const { name } = JSON.parse(readFileSync(manifest, 'utf8'));
    if (typeof name === 'string') names.add(name);
  }
  return names;
}
const WORKSPACE_PACKAGES = workspacePackageNames();

// Drizzle is forbidden everywhere except schema (which DEFINEs the Drizzle
// schemas). The workspace-scope rule applies to every root.
const RULES = [
  { root: 'packages/schema/src', forbidden: [] },
  { root: 'packages/persistence/src', forbidden: DRIZZLE },
  { root: 'packages/local-ops/src', forbidden: DRIZZLE },
  { root: 'packages/dashboard-ui/src', forbidden: DRIZZLE },
  { root: 'web-ui/app', forbidden: DRIZZLE },
  { root: 'cli/src', forbidden: DRIZZLE },
  { root: 'packages/ui-kit/src', forbidden: DRIZZLE },
  { root: 'packages/detections/src', forbidden: DRIZZLE },
  { root: 'packages/extract/src', forbidden: DRIZZLE },
  { root: 'packages/scanner/src', forbidden: DRIZZLE },
  { root: 'packages/plugin-sdk/src', forbidden: DRIZZLE },
  { root: 'packages/plugin-runtime/src', forbidden: DRIZZLE },
  { root: 'plugins/claude-code/src', forbidden: DRIZZLE },
];

// Roots scanned for a stray fetch() call — the whole shipped surface.
const FETCH_ROOTS = [
  'packages/schema/src',
  'packages/persistence/src',
  'packages/local-ops/src',
  'packages/dashboard-ui/src',
  'packages/ui-kit/src',
  'packages/detections/src',
  'packages/extract/src',
  'packages/scanner/src',
  'packages/plugin-sdk/src',
  'packages/plugin-runtime/src',
  'web-ui/app',
  'cli/src',
  'plugins/claude-code/src',
];

// Fail loud if a configured root has vanished (e.g. a folder move left a stale path) — a
// silently-skipped root would stop enforcing the wall exactly where it matters.
const allRoots = [...new Set([...RULES.map((r) => r.root), ...FETCH_ROOTS])];
const missing = allRoots.filter((root) => !existsSync(root));
if (missing.length > 0) {
  process.stderr.write(
    `OSS boundary check misconfigured — configured root(s) not found:\n${missing.map((m) => `  ${m}`).join('\n')}\nUpdate scripts/check-oss-boundaries.mjs after any folder move.\n`,
  );
  process.exit(1);
}
if (WORKSPACE_PACKAGES.size === 0) {
  process.stderr.write(
    'OSS boundary check misconfigured — no workspace package.json manifests found.\n',
  );
  process.exit(1);
}

const IMPORT_LINE = /\b(?:from|import|require)\b/;
const SOURCE = /\.(?:ts|tsx|mts|cts)$/;

function* walk(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // root absent on this branch — skip
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (SOURCE.test(e.name)) yield p;
  }
}

// A forbidden specifier used as a module path: quoted, exact or a subpath prefix.
function importsSpec(line, spec) {
  return (
    line.includes(`'${spec}'`) ||
    line.includes(`"${spec}"`) ||
    line.includes(`'${spec}/`) ||
    line.includes(`"${spec}/`)
  );
}

// Every quoted @akasecurity/* specifier on the line, reduced to its package
// name (scope + first path segment).
function scopedPackagesOn(line) {
  const packages = [];
  for (const match of line.matchAll(/['"](@akasecurity\/[^'"/]+)(?:\/[^'"]*)?['"]/g)) {
    packages.push(match[1]);
  }
  return packages;
}

// Strip string literals and comments so a fetch() mentioned in prose or fixture data
// isn't mistaken for a real call. Blank quoted strings first (single/double/backtick),
// then drop line/block-comment bodies, then look for a fetch( call.
function callsFetch(line) {
  const trimmed = line.trimStart();
  if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return false;
  const code = line
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/`(?:[^`\\]|\\.)*`/g, '``')
    .replace(/\/\/.*$/, '');
  return /\bfetch\s*\(/.test(code);
}

const violations = [];
for (const { root, forbidden } of RULES) {
  for (const file of walk(root)) {
    readFileSync(file, 'utf8')
      .split('\n')
      .forEach((line, i) => {
        if (!IMPORT_LINE.test(line)) return;
        for (const spec of forbidden) {
          if (importsSpec(line, spec)) violations.push(`${file}:${String(i + 1)}  imports ${spec}`);
        }
        for (const pkg of scopedPackagesOn(line)) {
          if (!WORKSPACE_PACKAGES.has(pkg)) {
            violations.push(`${file}:${String(i + 1)}  imports non-workspace package ${pkg}`);
          }
        }
      });
  }
}

const fetchViolations = [];
for (const root of FETCH_ROOTS) {
  for (const file of walk(root)) {
    readFileSync(file, 'utf8')
      .split('\n')
      .forEach((line, i) => {
        if (callsFetch(line)) fetchViolations.push(`${file}:${String(i + 1)}  calls fetch()`);
      });
  }
}

if (violations.length > 0) {
  process.stderr.write(
    'OSS boundary violation — open-source packages must not import Drizzle or non-workspace scope packages:\n',
  );
  for (const v of violations) process.stderr.write(`  ${v}\n`);
  process.stderr.write(
    '\nThe OSS surface reads the local store via @akasecurity/persistence. See CLAUDE.md "Package dependency rules".\n',
  );
}

if (fetchViolations.length > 0) {
  process.stderr.write(
    '\nOSS network violation — the OSS surface is local-only and must not call fetch():\n',
  );
  for (const v of fetchViolations) process.stderr.write(`  ${v}\n`);
  process.stderr.write(
    '\nOSS talks to no AKA service; the only network access is package-manager shell-outs in @akasecurity/local-ops. See CLAUDE.md "Package dependency rules".\n',
  );
}

if (violations.length > 0 || fetchViolations.length > 0) process.exit(1);

process.stdout.write(
  `OSS boundary check passed (${String(RULES.length)} import roots, ${String(FETCH_ROOTS.length)} fetch roots scanned, no violations).\n`,
);
