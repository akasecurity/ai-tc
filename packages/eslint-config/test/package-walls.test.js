import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { ESLint, Linter } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

import { REPO_ROOT, trackedFiles } from './helpers/lint-invocations.js';

// Which packages actually GET each shared wall. Every other suite in this
// package lints a rule value imported from ../src/index.js, which stays green
// whether or not a single config spreads it — so this is the only file that can
// tell a wired package from an unwired one.
//
// It is ONE file resolving each package once, deliberately. Resolving a flat
// config pulls the whole typescript-eslint stack and is filesystem- and
// resolution-bound; two suites each resolving the same configs in their own
// worker cost twice that in parallel, and on a contended runner they push each
// OTHER past vitest's per-test and per-hook defaults. That is not hypothetical:
// splitting this across two files timed out neighbouring suites here, with the
// failures landing on whichever file lost the race rather than on the change.
// Anything new that needs a resolved per-package config belongs in this file.
const RESOLVE_TIMEOUT_MS = 60_000;

/**
 * Every package carrying a shared wall, and a real source file in each.
 * `tonal` marks the three that render Tailwind classes.
 */
const WALLED_PACKAGES = [
  { name: '@akasecurity/persistence', dir: 'packages/persistence', file: 'src/index.ts' },
  { name: '@akasecurity/local-ops', dir: 'packages/local-ops', file: 'src/index.ts' },
  { name: '@akasecurity/ui-kit', dir: 'packages/ui-kit', file: 'src/badge.tsx', tonal: true },
  {
    name: '@akasecurity/dashboard-ui',
    dir: 'packages/dashboard-ui',
    file: 'src/findings/meta.ts',
    tonal: true,
  },
  { name: 'web-ui', dir: 'web-ui', file: 'app/components/AppShell.tsx', tonal: true },
];

// @akasecurity/schema is the one package that must NOT carry the drizzle wall:
// it is where Drizzle is imported, to DEFINE the local-store and registry
// schemas.
const WALL_EXEMPT_PACKAGES = ['packages/schema'];

/** @type {Map<string, import('eslint').Linter.Config['rules']>} */
const resolved = new Map();

beforeAll(async () => {
  for (const pkg of WALLED_PACKAGES) {
    const pkgDir = join(REPO_ROOT, pkg.dir);
    const eslint = new ESLint({ cwd: pkgDir });
    const config = await eslint.calculateConfigForFile(join(pkgDir, pkg.file));
    resolved.set(pkg.name, config.rules);
  }
}, RESOLVE_TIMEOUT_MS);

const linter = new Linter();

/** How many messages `code` produces under `name`'s REAL resolved rule. */
const firedIn = (name, code, rule) =>
  linter.verify(code, {
    languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
    rules: { [rule]: resolved.get(name)?.[rule] },
  }).length;

const names = WALLED_PACKAGES.map((p) => p.name);
const tonalNames = WALLED_PACKAGES.filter((p) => p.tonal).map((p) => p.name);

describe('every walled package resolves a config at all', () => {
  it.each(names)('%s', (name) => {
    expect(resolved.get(name), `${name} resolved no rules`).toBeDefined();
  });
});

// The two rules the walls set are REPLACED rather than merged by a later
// flat-config entry, so the order a package spreads them in decides whether the
// ban survives — and a lost ban still exits 0. These drive the resolved value,
// so a reordering regression fails here rather than shipping.
describe('the drizzle wall reaches every package that reads the store', () => {
  it.each(names)('%s rejects a static drizzle import', (name) => {
    expect(firedIn(name, "import { eq } from 'drizzle-orm';", 'no-restricted-imports')).toBe(1);
    expect(firedIn(name, "import { p } from 'drizzle-orm/pg-core';", 'no-restricted-imports')).toBe(
      1,
    );
  });

  it.each(names)('%s rejects a companion package that pulls drizzle-orm', (name) => {
    expect(firedIn(name, "import z from 'drizzle-zod';", 'no-restricted-imports')).toBe(1);
  });

  // The half a specifier ban structurally cannot see. A code-split
  // `await import('drizzle-orm/pg-core')` is how a heavy dependency reaches a
  // browser bundle without the static form ever being written.
  it.each(names)('%s rejects a DYNAMIC drizzle import', (name) => {
    expect(firedIn(name, "await import('drizzle-orm/pg-core');", 'no-restricted-syntax')).toBe(1);
    expect(firedIn(name, "require('drizzle-zod');", 'no-restricted-syntax')).toBe(1);
  });

  it.each(names)('%s still enforces the network ban (static and dynamic)', (name) => {
    expect(firedIn(name, "import a from 'axios';", 'no-restricted-imports')).toBe(1);
    expect(firedIn(name, "await import('node:http');", 'no-restricted-syntax')).toBe(1);
  });

  // A relative specifier that merely starts with the banned prefix is not a
  // package import. Without this the ban could be "fixed" into a prefix match
  // that also rejects ./drizzle-helpers.js, and every case above stays green.
  it.each(names)('%s does not flag a relative path starting with drizzle-', (name) => {
    expect(firedIn(name, "import x from './drizzle-helpers.js';", 'no-restricted-imports')).toBe(0);
  });
});

describe('the tonal-ink wall reaches every package that renders Tailwind classes', () => {
  it.each(tonalNames)('%s rejects a hue used as text', (name) => {
    expect(firedIn(name, "const c = 'text-sev-critical';", 'no-restricted-syntax')).toBe(1);
  });

  it.each(tonalNames)('%s still enforces the network ban', (name) => {
    expect(firedIn(name, "await import('node:http');", 'no-restricted-syntax')).toBe(1);
  });
});

// Derived from the tree rather than listed, so a package added without the wall
// fails here. A floor would forbid removals while letting the next unguarded
// package in, which is the direction this drifts.
describe('the drizzle wall covers an exact set of packages, not a floor', () => {
  const WALL_TOKENS = ['noDrizzleImports', 'reactUiPackage'];

  const configsReferencingWall = () =>
    trackedFiles()
      .filter((f) => /(^|\/)eslint\.config\.mjs$/.test(f))
      .filter((f) => {
        const src = readFileSync(join(REPO_ROOT, f), 'utf8');
        return WALL_TOKENS.some((token) => src.includes(token));
      })
      .map((f) => f.replace(/\/eslint\.config\.mjs$/, ''))
      .sort();

  it('is exactly the packages that read the store', () => {
    expect(
      configsReferencingWall(),
      'The set of packages wiring the drizzle wall changed. A package that reads the local ' +
        'store — or renders it in a browser — must spread `noDrizzleImports` (or `reactUiPackage`, ' +
        'which composes it) so drizzle-orm cannot reach it or its bundle. Update WALLED_PACKAGES ' +
        'here if that was deliberate; @akasecurity/schema is the one package that must NOT carry ' +
        'it, since that is where Drizzle defines the schema.',
    ).toEqual(WALLED_PACKAGES.map((p) => p.dir).sort());
  });

  it('never reaches @akasecurity/schema, where Drizzle is defined', () => {
    const walled = configsReferencingWall();
    for (const dir of WALL_EXEMPT_PACKAGES) {
      expect(walled, `${dir} must not carry the wall`).not.toContain(dir);
    }
  });
});
