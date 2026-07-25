import { existsSync, globSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ESLint, Linter } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

// This file guards the per-package ESLint configs two ways.
//
//  1. STRUCTURAL (the `#50` block): every workspace package — enumerated from
//     pnpm-workspace.yaml, not a hand-maintained glob — must ship an
//     eslint.config.mjs that extends `@akasecurity/eslint-config`, unless it is
//     on an explicit, reasoned opt-out list. A package with NO config at all is
//     invisible to `pnpm lint` (nothing points ESLint at it) AND to a glob that
//     only ever matched existing config files, so it would ship UNGUARDED for
//     network calls with CI green. The floor assertion alone cannot catch a
//     package that was never in the glob's universe — this block can.
//
//  2. BEHAVIORAL (the composition / last-wins block): resolve each real
//     eslint.config.mjs through ESLint and assert the four network rules still
//     fire on real code. Flat config resolves "last wins": the final block
//     matching a file overrides earlier ones for a given rule, and
//     no-restricted-imports never merges across blocks. So a package that layers
//     a second config on top of base (web-ui: react + noEnterpriseImports;
//     persistence / local-ops: base + noEnterpriseImports; cli: base + the
//     dashboard opt-out) could silently drop a network ban with the unit suite
//     still green. Here we assert the composition, not the components.
//
// The two compose into a closed loop: (1) guarantees every package ships a
// config, (2) is fed the same derived list and proves each config enforces the
// ban. A new package that forgets its config fails (1); one whose config fails
// to wire the ban fails (2).

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

// --- Workspace package enumeration (derived from pnpm-workspace.yaml) --------

// Packages exempt from shipping a network-guarded eslint.config.mjs, keyed by
// package name. Keep this list TINY — every entry is a hole in the no-network
// enforcement and must be a deliberate, reviewed decision, so each carries its
// reason. A package that ships lintable source belongs behind the ban, not here.
const CONFIG_OPT_OUT = [
  {
    name: '@akasecurity/eslint-config',
    reason:
      'Defines the shared config; it cannot extend itself, and its own `lint` script is a no-op.',
  },
];
const OPT_OUT_NAMES = new Set(CONFIG_OPT_OUT.map((o) => o.name));

// "Extends `@akasecurity/eslint-config`" = imports it (the root entry or the
// `/react` sub-entry) via `import ... from` or `require(...)`. This is the fast,
// readable statement of intent for the acceptance criterion; the BEHAVIORAL
// suite below is what actually proves the import wires all four network rules,
// so a config that imports the package but forgets to spread `...base` is caught
// there, not here.
const IMPORTS_SHARED_CONFIG =
  /(?:import[^;]*from[ \t]*|require\([ \t]*)['"]@akasecurity\/eslint-config(?:\/[\w.-]+)?['"]/;

/**
 * The package globs declared under `packages:` in pnpm-workspace.yaml. Parsed
 * without a YAML dependency: capture the `packages:` line plus the consecutive
 * indented `- …` sequence entries that follow it (stopping at the next key that
 * starts in column 0), then pull each quoted-or-bare scalar.
 * @returns {string[]}
 */
function workspaceGlobs() {
  // Normalize CRLF → LF up front: the block/scalar regexes anchor on `\n`, and a
  // Windows checkout (core.autocrlf) would otherwise capture a trailing `\r` into
  // each glob and break globSync.
  const raw = readFileSync(join(REPO_ROOT, 'pnpm-workspace.yaml'), 'utf8').replace(/\r\n/g, '\n');
  const block = raw.match(/^packages:[ \t]*\n((?:[ \t]+-.*\n?)+)/m)?.[1] ?? '';
  return [...block.matchAll(/^[ \t]+-[ \t]*['"]?([^'"\n#]+?)['"]?[ \t]*$/gm)].map((m) => m[1]);
}

/**
 * Every workspace package on disk, resolved from pnpm-workspace.yaml exactly as
 * pnpm does: expand each glob, keep the directories that hold a package.json.
 * @returns {{ name: string, dir: string, configRel: string, hasConfig: boolean, extendsShared: boolean }[]}
 */
function discoverWorkspacePackages() {
  const dirs = [
    ...new Set(
      workspaceGlobs()
        .flatMap((g) => globSync(g, { cwd: REPO_ROOT }))
        .filter((rel) => existsSync(join(REPO_ROOT, rel, 'package.json'))),
    ),
  ].sort();
  return dirs.map((dir) => {
    const pkg = JSON.parse(readFileSync(join(REPO_ROOT, dir, 'package.json'), 'utf8'));
    const configRel = join(dir, 'eslint.config.mjs');
    const configAbs = join(REPO_ROOT, configRel);
    const hasConfig = existsSync(configAbs);
    return {
      name: pkg.name,
      dir,
      configRel,
      hasConfig,
      extendsShared: hasConfig && IMPORTS_SHARED_CONFIG.test(readFileSync(configAbs, 'utf8')),
    };
  });
}

const WORKSPACE_PACKAGES = discoverWorkspacePackages();

// The packages that MUST ship a network-guarded config (everything except the
// opt-outs). Fed to both the structural guard and the behavioral suite.
const GUARDED_PACKAGES = WORKSPACE_PACKAGES.filter((p) => !OPT_OUT_NAMES.has(p.name));

/**
 * Split the guarded packages by how they fail the config requirement. Pure over
 * its input so the failure paths are testable with synthetic packages — a real,
 * healthy tree produces none by construction.
 * @param {{ name: string, hasConfig: boolean, extendsShared: boolean }[]} guarded
 * @returns {{ missing: string[], notExtending: string[] }}
 */
function configViolations(guarded) {
  return {
    missing: guarded.filter((p) => !p.hasConfig).map((p) => p.name),
    notExtending: guarded.filter((p) => p.hasConfig && !p.extendsShared).map((p) => p.name),
  };
}

// The per-package configs the BEHAVIORAL suite resolves through ESLint. Derived
// from the workspace enumeration (not a hand-maintained glob with `cli`/`web-ui`
// spelled out) so a new package's config is behaviorally verified the moment it
// is added — and the structural guard guarantees every guarded package
// contributes exactly one entry here.
const CONFIG_FILES = GUARDED_PACKAGES.filter((p) => p.hasConfig).map((p) => p.configRel);

// --- Behavioral resolution helpers (shared by the composition suite) ---------

const KEYS = /** @type {const} */ ([
  'no-restricted-globals',
  'no-restricted-properties',
  'no-restricted-imports',
  'no-restricted-syntax',
]);

// One snippet that must trip all four network rules at once: a banned import, a
// bare global, a dynamic import, and the container-global member bypass.
const NETWORK_SNIPPET = [
  "import x from 'axios';",
  "fetch('/x');",
  "await import('undici');",
  'globalThis.fetch();',
].join('\n');

const linter = new Linter();
const LANG = { ecmaVersion: 'latest', sourceType: 'module' };

// Resolving a real config through ESLint (`new ESLint` + `calculateConfigForFile`)
// is slow on a cold runner: the first call loads the whole typescript-eslint +
// plugin stack and, for a large package like cli, can take several seconds —
// past a default per-test timeout. So every resolution happens in a `beforeAll`
// with a generous budget, and the tests themselves are fast assertions on the
// cached result.
const RESOLVE_TIMEOUT_MS = 120_000;

/**
 * Resolve the effective config a package's real eslint.config.mjs produces for
 * `relFile`, and return just the four network rules from it. calculateConfigForFile
 * runs the full flat-config cascade without parsing the file, so it needs no
 * type information and the probe path need not exist.
 * @param {string} pkgDir absolute package directory
 * @param {string} relFile path within the package to resolve config for
 */
async function resolveNetworkRules(pkgDir, relFile) {
  const eslint = new ESLint({ cwd: pkgDir, overrideConfigFile: join(pkgDir, 'eslint.config.mjs') });
  const config = await eslint.calculateConfigForFile(join(pkgDir, relFile));
  return Object.fromEntries(KEYS.map((k) => [k, config.rules?.[k]]));
}

/** Which network rule ids fire when `code` is linted with `rules`. */
function firedRuleIds(code, rules) {
  return new Set(linter.verify(code, { languageOptions: LANG, rules }).map((m) => m.ruleId));
}

// --- Structural guard: every package ships a network-guarded config (#50) -----

describe('every workspace package ships a network-guarded eslint config (#50)', () => {
  it('discovered the workspace packages (guard against a vacuous pass)', () => {
    // A broken pnpm-workspace.yaml parse would leave the enumeration empty and
    // every assertion in this file would pass vacuously. 14 workspace packages
    // exist today; 13 ship a config (all but @akasecurity/eslint-config).
    expect(workspaceGlobs().length).toBeGreaterThan(0);
    expect(WORKSPACE_PACKAGES.length).toBeGreaterThanOrEqual(12);
    expect(CONFIG_FILES.length).toBeGreaterThanOrEqual(11);
  });

  it('enumeration includes the non-packages/* roots (cli, web-ui, plugin)', () => {
    // The gap this test removed was a hand-maintained list that spelled out
    // `cli`/`web-ui` and globbed only three parent dirs. Pin that the derived
    // enumeration reaches the roots outside `packages/*`, so a parser regression
    // that dropped them fails here rather than silently under-covering.
    const names = new Set(WORKSPACE_PACKAGES.map((p) => p.name));
    for (const anchor of [
      '@akasecurity/cli',
      '@akasecurity/web-ui',
      '@akasecurity/ai-tc-claude-code',
    ]) {
      expect(names, anchor).toContain(anchor);
    }
  });

  it('no guarded package is missing its eslint.config.mjs', () => {
    const { missing } = configViolations(GUARDED_PACKAGES);
    expect(
      missing,
      missing.length
        ? 'These workspace packages ship no eslint.config.mjs, so `pnpm lint` never points ESLint at ' +
            'them and they would ship UNGUARDED for network calls with CI green. Add an ' +
            'eslint.config.mjs extending @akasecurity/eslint-config (see any sibling package), or — ' +
            'only if the package genuinely ships no self-lintable source — add it to CONFIG_OPT_OUT ' +
            `with a reason:\n  ${missing.join('\n  ')}`
        : undefined,
    ).toEqual([]);
  });

  it('every shipped config extends @akasecurity/eslint-config', () => {
    const { notExtending } = configViolations(GUARDED_PACKAGES);
    expect(
      notExtending,
      notExtending.length
        ? 'These packages ship an eslint.config.mjs that never imports @akasecurity/eslint-config, ' +
            'so the shared no-network ban is not wired in. Extend the shared config (spread ' +
            `...base / ...noEnterpriseImports / ...react):\n  ${notExtending.join('\n  ')}`
        : undefined,
    ).toEqual([]);
  });
});

describe('CONFIG_OPT_OUT hygiene', () => {
  const names = new Set(WORKSPACE_PACKAGES.map((p) => p.name));

  it.each(CONFIG_OPT_OUT)('$name is a real workspace package (no stale opt-out)', ({ name }) => {
    expect(names).toContain(name);
  });

  it('stays minimal — only @akasecurity/eslint-config is exempt today', () => {
    // Hard-coded so ANY addition to the opt-out is a reviewed change here rather
    // than a silent hole in the no-network enforcement (mirrors the ban-set
    // drift guards in no-network.test.js).
    expect(CONFIG_OPT_OUT.map((o) => o.name)).toEqual(['@akasecurity/eslint-config']);
  });
});

describe('configViolations (the guard mechanism, tested on synthetic packages)', () => {
  // The real tree is healthy, so the failure paths above never execute against
  // it. Exercise them directly to prove the guard fails LOUDLY and NAMES the
  // offending package — the second acceptance criterion of #50.
  it('names a package that ships no config', () => {
    const v = configViolations([
      { name: '@akasecurity/newpkg', hasConfig: false, extendsShared: false },
    ]);
    expect(v.missing).toEqual(['@akasecurity/newpkg']);
    expect(v.notExtending).toEqual([]);
  });

  it('names a package whose config does not extend the shared config', () => {
    const v = configViolations([
      { name: '@akasecurity/newpkg', hasConfig: true, extendsShared: false },
    ]);
    expect(v.notExtending).toEqual(['@akasecurity/newpkg']);
    expect(v.missing).toEqual([]);
  });

  it('clears a package that ships a config extending the shared config', () => {
    const v = configViolations([{ name: '@akasecurity/ok', hasConfig: true, extendsShared: true }]);
    expect(v.missing).toEqual([]);
    expect(v.notExtending).toEqual([]);
  });

  it('reports every offender in a mixed set (fails loudly, not on the first)', () => {
    const v = configViolations([
      { name: '@akasecurity/a', hasConfig: false, extendsShared: false },
      { name: '@akasecurity/b', hasConfig: true, extendsShared: true },
      { name: '@akasecurity/c', hasConfig: true, extendsShared: false },
      { name: '@akasecurity/d', hasConfig: false, extendsShared: false },
    ]);
    expect(v.missing).toEqual(['@akasecurity/a', '@akasecurity/d']);
    expect(v.notExtending).toEqual(['@akasecurity/c']);
  });
});

// --- Behavioral guard: each config actually enforces the ban -----------------

describe('effective per-package config (composition / last-wins)', () => {
  /** @type {Map<string, Set<string>>} configRel -> rule ids the snippet trips */
  const firedByConfig = new Map();

  beforeAll(async () => {
    for (const configRel of CONFIG_FILES) {
      const pkgDir = join(REPO_ROOT, dirname(configRel));
      // A source path base applies to; it need not exist (config is computed,
      // not parsed). Avoids each package's real layout while still hitting base.
      const rules = await resolveNetworkRules(pkgDir, 'src/__network_ban_probe__.ts');
      firedByConfig.set(configRel, firedRuleIds(NETWORK_SNIPPET, rules));
    }
  }, RESOLVE_TIMEOUT_MS);

  it('resolved a config for every guarded package (no behavioral gap)', () => {
    // The structural guard guarantees every guarded package ships a config;
    // pin that the behavioral suite actually resolved one for each, so a package
    // can never be present-but-unverified.
    expect(CONFIG_FILES.length).toBe(GUARDED_PACKAGES.length);
  });

  it.each(CONFIG_FILES)('bans every network form in %s', (configRel) => {
    const fired = firedByConfig.get(configRel);
    for (const key of KEYS) {
      expect(fired, `${configRel} :: ${key}`).toContain(key);
    }
  });
});

describe('cli dashboard.ts file-scoped opt-out (real config)', () => {
  const cliDir = join(REPO_ROOT, 'cli');
  // Resolved network rules for two cli files, populated in beforeAll (see the
  // RESOLVE_TIMEOUT_MS note): dashboard.ts carries the node:net opt-out, the
  // other file must not.
  const resolved = { dashboard: undefined, otherFile: undefined };

  beforeAll(async () => {
    resolved.dashboard = await resolveNetworkRules(cliDir, 'src/commands/dashboard.ts');
    resolved.otherFile = await resolveNetworkRules(cliDir, 'src/lib/open-url.ts');
  }, RESOLVE_TIMEOUT_MS);

  it('allows node:net in dashboard.ts (the 127.0.0.1 bind probe)', () => {
    expect(firedRuleIds("import { createServer } from 'node:net';", resolved.dashboard).size).toBe(
      0,
    );
    // Symmetric: the dynamic form is opted out too.
    expect(firedRuleIds("await import('node:net');", resolved.dashboard).size).toBe(0);
  });

  it('still bans every OTHER network module in dashboard.ts', () => {
    expect(firedRuleIds("import http from 'node:http';", resolved.dashboard)).toContain(
      'no-restricted-imports',
    );
    expect(firedRuleIds("fetch('/x');", resolved.dashboard)).toContain('no-restricted-globals');
  });

  it('does NOT leak the node:net opt-out to other cli files', () => {
    expect(firedRuleIds("import { createServer } from 'node:net';", resolved.otherFile)).toContain(
      'no-restricted-imports',
    );
  });
});
