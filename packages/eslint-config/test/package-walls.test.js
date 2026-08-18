import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { ESLint, Linter } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

import { REPO_ROOT, toPosix, trackedEslintConfigFiles } from './helpers/lint-invocations.js';

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
//
// The budget is charged per RESOLUTION, and the wall now reaches every package
// that reads the store rather than five of them, so this hook resolves 13
// configs where it once resolved 5. The ceiling is sized against that count on a
// contended runner, not against the ~4s it takes on an idle machine — a hook
// that overruns is reported as a timeout, which reads as a budget failure and is
// not one.
const RESOLVE_TIMEOUT_MS = 120_000;

/**
 * Every package carrying a shared wall, and a real source file in each.
 * `tonal` marks the three that render Tailwind classes.
 */
const WALLED_PACKAGES = [
  { name: '@akasecurity/persistence', dir: 'packages/persistence', file: 'src/index.ts' },
  { name: '@akasecurity/local-ops', dir: 'packages/local-ops', file: 'src/index.ts' },
  { name: '@akasecurity/plugin-sdk', dir: 'packages/plugin-sdk', file: 'src/config-inventory.ts' },
  { name: '@akasecurity/plugin-runtime', dir: 'packages/plugin-runtime', file: 'src/index.ts' },
  { name: '@akasecurity/scanner', dir: 'packages/scanner', file: 'src/index.ts' },
  // The four self-contained bundles. `noExternal: [/^@akasecurity\//]` inlines
  // every workspace package they use, so a Drizzle import in any of these ships
  // to users in a published artifact — which is why they matter MORE here than
  // the library packages above, not less.
  { name: '@akasecurity/cli', dir: 'cli', file: 'src/cli.ts' },
  {
    name: '@akasecurity/ai-tc-claude-code',
    dir: 'plugins/claude-code',
    file: 'src/backfill.ts',
  },
  { name: '@akasecurity/ai-tc-codex', dir: 'plugins/codex', file: 'src/backfill.ts' },
  { name: '@akasecurity/ai-tc-antigravity', dir: 'plugins/antigravity', file: 'src/backfill.ts' },
  { name: '@akasecurity/ui-kit', dir: 'packages/ui-kit', file: 'src/badge.tsx', tonal: true },
  {
    name: '@akasecurity/dashboard-ui',
    dir: 'packages/dashboard-ui',
    file: 'src/findings/meta.ts',
    tonal: true,
  },
  { name: 'web-ui', dir: 'web-ui', file: 'app/components/AppShell.tsx', tonal: true },
];

// A file whose config RELAXES the network ban. Such an entry sets
// `no-restricted-imports` itself, and flat config replaces rather than merges,
// so it silently drops the wall for that file unless it restates it — which is
// what `drizzleWallRules({ allow })` is for. Resolved per FILE, because the
// package-level config says nothing about what happens here.
const RELAXED_FILES = [
  {
    name: '@akasecurity/cli src/commands/dashboard.ts',
    dir: 'cli',
    file: 'src/commands/dashboard.ts',
    allowed: 'node:net',
  },
];

// @akasecurity/schema is the one package that must NOT carry the drizzle wall:
// it is where Drizzle is imported, to DEFINE the local-store and registry
// schemas.
//
// This feeds the exact-set assertion's failure MESSAGE rather than a case of its
// own. A separate `not.toContain` case could not fail unless the exact-set
// assertion had already failed — the set is compared by equality, so a wall
// appearing here fails there first — while costing a second full walk of the
// tracked tree. What the exemption is worth is the explanation, and that belongs
// where somebody meets the failure.
const WALL_EXEMPT_PACKAGES = ['packages/schema'];

/** @type {Map<string, import('eslint').Linter.Config['rules']>} */
const resolved = new Map();

// Resolution uses ORDINARY flat-config lookup, which finds only the conventional
// `eslint.config.*`. Discovery below does not — it derives by basename, so it
// sees a wall wired in a `-c`-named config. The two halves therefore disagree
// for a package whose only config is oddly named, and that disagreement is
// surfaced HERE rather than left to surface as ESLint's own bare "Could not find
// config file", which names neither the package nor the reason.
beforeAll(async () => {
  for (const pkg of [...WALLED_PACKAGES, ...RELAXED_FILES]) {
    const pkgDir = join(REPO_ROOT, pkg.dir);
    const eslint = new ESLint({ cwd: pkgDir });
    let config;
    try {
      config = await eslint.calculateConfigForFile(join(pkgDir, pkg.file));
    } catch (cause) {
      throw new Error(
        `Could not resolve a config for ${pkg.name} (${pkg.dir}/${pkg.file}). This suite drives ` +
          'the REAL resolved rules, so it needs ordinary flat-config lookup to find that ' +
          `package's config — i.e. a conventional \`eslint.config.*\` at ${pkg.dir}. A config ` +
          'reachable only through a `-c` flag is discovered by the exact-set assertion below but ' +
          'cannot be resolved here; give the package a conventional config, or drive this one ' +
          'through `overrideConfigFile`.',
        { cause },
      );
    }
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
  const WALL_TOKENS = ['noDrizzleImports', 'reactUiPackage', 'drizzleWallRules'];

  // Discovered by BASENAME, via the same helper the no-network audit derives
  // from — never a hardcoded `eslint.config.mjs`. ESLint honours `-c
  // eslint.anything.config.mjs` exactly like the conventional name, so a
  // filename glob is a hole one rename wide: a package that moved its wall into
  // a secondary config would lose it with this staying green, and one that wired
  // the wall ONLY in a `-c`-named config would read as unwalled and fail below
  // for a reason that is not true.
  //
  // A config's owner is its directory, and a repo-root config owns '.' — which
  // is why this takes the dirname rather than stripping a known suffix. Two
  // configs in one directory collapse to one entry, so a package that splits its
  // wall across a primary and a scripts config still reads as one package.
  const configsReferencingWall = () =>
    [
      ...new Set(
        trackedEslintConfigFiles()
          .filter((f) => {
            const src = readFileSync(join(REPO_ROOT, f), 'utf8');
            return WALL_TOKENS.some((token) => src.includes(token));
          })
          .map((f) => {
            const dir = toPosix(f).split('/').slice(0, -1).join('/');
            return dir === '' ? '.' : dir;
          }),
      ),
    ].sort();

  it('is exactly the packages that read the store', () => {
    expect(
      configsReferencingWall(),
      'The set of packages wiring the drizzle wall changed. A package that reads the local ' +
        'store — or renders it in a browser — must spread `noDrizzleImports` (or `reactUiPackage`, ' +
        'which composes it) so drizzle-orm cannot reach it or its bundle; that includes the four ' +
        'self-contained bundles (cli and the three plugins), where a Drizzle import would be ' +
        'INLINED into a published artifact. Update WALLED_PACKAGES here if that was deliberate. ' +
        `The one package that must NOT carry the wall is ${WALL_EXEMPT_PACKAGES.join(', ')}, ` +
        'since that is where Drizzle defines the local-store and registry schemas.',
    ).toEqual(WALLED_PACKAGES.map((p) => p.dir).sort());
  });
});

// A file-scoped entry that relaxes the network ban REPLACES the wall's rules for
// the files it matches, and a lost ban still exits 0. The package-level
// assertions above cannot see this: they resolve one ordinary source file, which
// no `files:` entry matches. This resolves the relaxed file itself.
describe('a file that relaxes the network ban keeps the wall', () => {
  it.each(RELAXED_FILES.map((f) => [f.name, f]))('%s', (_name, file) => {
    expect(firedIn(file.name, `import x from '${file.allowed}';`, 'no-restricted-imports')).toBe(0);

    expect(
      firedIn(file.name, "import { eq } from 'drizzle-orm';", 'no-restricted-imports'),
      `${file.name} relaxes the network ban and lost the drizzle wall with it — build its rules ` +
        'with drizzleWallRules({ allow }) rather than noNetworkImports({ allow }).',
    ).toBe(1);
    expect(firedIn(file.name, "import z from 'drizzle-zod';", 'no-restricted-imports')).toBe(1);
    expect(
      firedIn(file.name, "await import('drizzle-orm/sqlite-core');", 'no-restricted-syntax'),
    ).toBe(1);

    // The relaxation is scoped to the one module it names.
    expect(firedIn(file.name, "import h from 'node:http';", 'no-restricted-imports')).toBe(1);
  });
});
