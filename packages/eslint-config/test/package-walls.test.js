import { readFileSync } from 'node:fs';
import { join, sep } from 'node:path';

import { ESLint, Linter } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  REPO_ROOT,
  toPosix,
  toPosixPath,
  trackedEslintConfigFiles,
  workspacePackageDirs,
} from './helpers/lint-invocations.js';

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
// that ships product code rather than five of them, so this hook resolves 17
// configs where it once resolved 5. The ceiling is sized against that count on a
// contended runner, not against the few seconds it takes on an idle machine — a
// hook that overruns is reported as a timeout, which reads as a budget failure
// and is not one.
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
  // The self-contained bundles. `noExternal: [/^@akasecurity\//]` inlines every
  // workspace package they use, so a Drizzle import in any of these ships to
  // users in a published artifact — which is why they matter MORE here than the
  // library packages above, not less. browser-extension is one of them and is
  // the sharpest case: it sets the same `noExternal` and its MV3 content scripts
  // run in a page.
  { name: '@akasecurity/cli', dir: 'cli', file: 'src/cli.ts' },
  {
    name: '@akasecurity/ai-tc-claude-code',
    dir: 'plugins/claude-code',
    file: 'src/backfill.ts',
  },
  { name: '@akasecurity/ai-tc-codex', dir: 'plugins/codex', file: 'src/backfill.ts' },
  { name: '@akasecurity/ai-tc-antigravity', dir: 'plugins/antigravity', file: 'src/backfill.ts' },
  { name: '@akasecurity/detections', dir: 'packages/detections', file: 'src/engine.ts' },
  { name: '@akasecurity/extract', dir: 'packages/extract', file: 'src/csv.ts' },
  { name: '@akasecurity/setup-wizard', dir: 'packages/setup-wizard', file: 'src/index.ts' },
  {
    name: '@akasecurity/plugin-browser-extension',
    dir: 'plugins/browser-extension',
    file: 'src/content.ts',
  },
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

// The workspace packages that deliberately do NOT carry the drizzle wall, with
// the reason each is out. Every other workspace package is in WALLED_PACKAGES,
// and the coverage assertion below holds the two together — so a package added
// tomorrow fails until somebody decides which side it belongs on, rather than
// being silently absent from a list nothing derives.
//
// The first entry is also what feeds the exact-set assertion's failure MESSAGE
// rather than a case of its own. A separate `not.toContain` case could not fail
// unless the exact-set assertion had already failed — the set is compared by
// equality, so a wall appearing there fails first — while costing a second full
// walk of the tracked tree. What the exemption is worth is the explanation, and
// that belongs where somebody meets the failure.
const WALL_EXEMPT_PACKAGES = [
  {
    dir: 'packages/schema',
    why: 'where Drizzle is imported, to DEFINE the local-store and registry schemas',
  },
  {
    dir: 'packages/eslint-config',
    why: 'defines the wall itself; repo tooling, never shipped and never reads the store',
  },
  { dir: 'tools/audit-gate', why: 'repo tooling, never shipped' },
  { dir: 'tools/coverage-gate', why: 'repo tooling, never shipped' },
  { dir: 'tools/installer', why: 'repo tooling, never shipped' },
  { dir: 'tools/portability-gate', why: 'repo tooling, never shipped' },
];

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
describe('the drizzle wall reaches every package that ships product code', () => {
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

  it('is exactly the packages that ship product code', () => {
    expect(
      configsReferencingWall(),
      'The set of packages wiring the drizzle wall changed. Every workspace package that ships ' +
        'product code must spread `noDrizzleImports` (or `reactUiPackage`, which composes it), ' +
        'whether or not it reads the store today: the shipping bundles set ' +
        '`noExternal: [/^@akasecurity\\//]`, so ONE Drizzle import anywhere in that closure is ' +
        'inlined into a published artifact — and into a browser for the extension, web-ui, ' +
        'dashboard-ui and ui-kit. The exceptions are listed below, and they are the whole of the ' +
        'difference. Update WALLED_PACKAGES here if that was deliberate. ' +
        'Packages deliberately outside the wall, and why:\n  ' +
        WALL_EXEMPT_PACKAGES.map((e) => `${e.dir} — ${e.why}`).join('\n  '),
    ).toEqual(WALLED_PACKAGES.map((p) => p.dir).sort());
  });

  // The exact-set assertion above compares the tree against WALLED_PACKAGES, so
  // it cannot see a package that is in NEITHER list: absent from the tree's
  // walled set and absent from ours, it agrees with itself and passes. That is
  // how a package ships unwalled without anything going red — and, because the
  // comparison is by equality, the omission is then PINNED, since walling it
  // later fails until somebody edits the list.
  //
  // So the two lists have to account for every workspace package between them,
  // derived from pnpm-workspace.yaml rather than restated. A package added
  // tomorrow is a decision, not a default.
  // Normalizes its input, because the two lists are posix literals while
  // `workspacePackageDirs()` builds on `globSync`, which yields NATIVE
  // separators. Taking the dirs as an ARGUMENT rather than reading them is what
  // makes that testable: the separator this is wrong about is the one the
  // running host does not use, so a case driving the real tree can only fail on
  // Windows — where it did, reporting all 22 packages unaccounted for.
  const unaccountedIn = (dirs) => {
    const walled = new Set(WALLED_PACKAGES.map((p) => p.dir));
    const exempt = new Set(WALL_EXEMPT_PACKAGES.map((e) => e.dir));
    return dirs.map(toPosixPath).filter((d) => !walled.has(d) && !exempt.has(d));
  };

  it('accounts for every workspace package, walled or exempt', () => {
    const unaccounted = unaccountedIn(workspacePackageDirs());
    expect(
      unaccounted,
      'These workspace packages are in neither WALLED_PACKAGES nor WALL_EXEMPT_PACKAGES, so ' +
        'nothing here says whether drizzle-orm may reach them. Wire `noDrizzleImports` into the ' +
        'package and add it above, or add it to WALL_EXEMPT_PACKAGES with the reason it is out:' +
        `\n  ${unaccounted.join('\n  ')}`,
    ).toEqual([]);

    // And the reverse: a dir listed here that the workspace no longer has is a
    // rule kept alive for a package that is gone.
    const known = new Set(workspacePackageDirs());
    expect(
      [...WALLED_PACKAGES.map((p) => p.dir), ...WALL_EXEMPT_PACKAGES.map((e) => e.dir)]
        .filter((d) => !known.has(d))
        .sort(),
      'Listed here but not a workspace package any more.',
    ).toEqual([]);

    const walled = new Set(WALLED_PACKAGES.map((p) => p.dir));
    expect(
      WALL_EXEMPT_PACKAGES.map((e) => e.dir).filter((d) => walled.has(d)),
      'walled and exempt at once',
    ).toEqual([]);
  });

  // The same accounting over the same tree, spelled the way Windows hands it
  // back. An absence assertion on THIS host's dirs is vacuous — they carry no
  // backslash to find — so the Windows-shaped input has to be constructed, not
  // observed. Drop the `.map(toPosixPath)` above and this is the only case in
  // the workspace that goes red before CI does.
  it('accounts for them the same when the platform hands back native separators', () => {
    const nativeStyle = workspacePackageDirs().map((d) => d.split('/').join('\\'));
    expect(
      nativeStyle.some((d) => d.includes('\\')),
      'fixture built no windows path',
    ).toBe(true);
    expect(unaccountedIn(nativeStyle)).toEqual([]);
  });
});
