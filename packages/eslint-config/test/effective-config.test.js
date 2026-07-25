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
//     network calls with CI green. Enumerating from the manifest and pinning the
//     result as an EXACT set catches a package that was never in a config glob's
//     universe — which a floor over "configs that already exist" cannot.
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
 * Parse the package globs declared under `packages:` in a pnpm-workspace.yaml
 * document, without a YAML dependency. Pure over its input string so the parse —
 * the most fragile part of this file — is unit-tested on synthetic YAML below
 * (CRLF, interspersed comments, quoting) rather than only against the one real
 * on-disk manifest. Walks line by line: enter the block at a bare `packages:`
 * line, collect each `- <scalar>` sequence entry (quoted or bare), tolerate
 * blank and comment lines inside the block, and stop at the next column-0 key.
 * Flow style (`packages: [ … ]`) is intentionally NOT parsed — it yields an
 * empty list, which the vacuous-pass guard turns into a loud failure rather than
 * a silent under-enumeration.
 * @param {string} rawYaml
 * @returns {string[]}
 */
export function parseWorkspaceGlobs(rawYaml) {
  const globs = [];
  let inBlock = false;
  // Normalize CRLF → LF first so a Windows checkout (core.autocrlf) does not
  // trail a `\r` into each glob (which would break globSync).
  for (const rawLine of rawYaml.replace(/\r\n/g, '\n').split('\n')) {
    // Strip comments up front (workspace globs never contain `#`), so an inline
    // or whole-line comment neither terminates the block nor pollutes an entry.
    const line = rawLine.replace(/#.*$/, '');
    if (!inBlock) {
      if (/^packages:[ \t]*$/.test(line)) inBlock = true;
      continue;
    }
    if (/^\S/.test(line)) break; // a new column-0 key ends the packages block
    const m = line.match(/^[ \t]+-[ \t]*['"]?([^'"\n]+?)['"]?[ \t]*$/);
    if (m) globs.push(m[1].trim());
  }
  return globs;
}

/**
 * The package globs from the repo's real pnpm-workspace.yaml.
 * @returns {string[]}
 */
function workspaceGlobs() {
  return parseWorkspaceGlobs(readFileSync(join(REPO_ROOT, 'pnpm-workspace.yaml'), 'utf8'));
}

/**
 * Every workspace package on disk, resolved from pnpm-workspace.yaml: expand each
 * glob and keep the directories that hold a package.json. (The current manifest
 * declares no `!` exclusion globs; pnpm's negation semantics are not modeled.)
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

// The exact set of workspace packages expected on disk, pinned by name (sorted).
// This is the anti-vacuous drift guard for the enumeration: a hand-rolled
// pnpm-workspace.yaml parse that silently dropped ONE package would still clear a
// `>=` floor, and the `CONFIG_FILES.length === GUARDED_PACKAGES.length` equality
// cannot catch it either (a package absent from discovery is absent from both
// sides). An exact set fails loudly on any add / drop / rename — the same rigor
// CONFIG_OPT_OUT uses. Adding or removing a workspace package is a deliberate
// edit here (and, for a new package, of its eslint.config.mjs).
const EXPECTED_WORKSPACE_PACKAGE_NAMES = [
  '@akasecurity/ai-tc-claude-code',
  '@akasecurity/cli',
  '@akasecurity/dashboard-ui',
  '@akasecurity/detections',
  '@akasecurity/eslint-config',
  '@akasecurity/extract',
  '@akasecurity/local-ops',
  '@akasecurity/persistence',
  '@akasecurity/plugin-runtime',
  '@akasecurity/plugin-sdk',
  '@akasecurity/scanner',
  '@akasecurity/schema',
  '@akasecurity/ui-kit',
  '@akasecurity/web-ui',
];

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

// The source directories a package may ship code under, most-specific first.
const SOURCE_DIRS = /** @type {const} */ (['src', 'app']);

/**
 * A probe file path under the directory a package actually ships code in, so the
 * behavioral resolution exercises the config where its `files`-scoped blocks
 * apply. web-ui ships `app/` (no `src/`), so a hardcoded `src/` probe would
 * resolve a path web-ui never lints — the very last-wins/path-scoping mistake
 * this suite exists to catch. The file need not exist (config is computed, not
 * parsed); fall back to `src/` for the source-less case.
 * @param {string} pkgDir absolute package directory
 */
function probeRelPath(pkgDir) {
  const dir = SOURCE_DIRS.find((d) => existsSync(join(pkgDir, d))) ?? 'src';
  return `${dir}/__network_ban_probe__.ts`;
}

// --- Structural guard: every package ships a network-guarded config (#50) -----

describe('every workspace package ships a network-guarded eslint config (#50)', () => {
  it('enumerates exactly the expected workspace packages (drift guard)', () => {
    // Pinned as an EXACT set, not a `>=` floor: a hand-rolled pnpm-workspace.yaml
    // parse that silently dropped one package would clear a floor AND the
    // behavioral CONFIG_FILES===GUARDED equality (both derive from the same parse
    // and drop it together), so that package would ship UNGUARDED with CI green —
    // the exact failure this file exists to prevent, through its least-tested
    // code. The explicit `workspaceGlobs()` check keeps the failure legible when
    // the parser is the culprit (empty ⇒ manifest reformatted / flow-style).
    expect(workspaceGlobs().length, 'pnpm-workspace.yaml parsed to zero globs').toBeGreaterThan(0);
    expect([...WORKSPACE_PACKAGES.map((p) => p.name)].sort()).toEqual(
      [...EXPECTED_WORKSPACE_PACKAGE_NAMES].sort(),
    );
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

describe('parseWorkspaceGlobs (the manifest parser, tested on synthetic YAML)', () => {
  // The real tree is parsed from one well-formed LF file on a Unix runner, so the
  // parser's edge-case handling (CRLF, interspersed comments, quoting, block
  // termination) is otherwise never exercised — including on Windows, where the
  // CRLF branch matters and this package is absent from the CI filter. Pin it
  // here so a parser regression fails loudly instead of silently under-counting.
  const BLOCK = `packages:\n  - 'packages/*'\n  - 'cli'\n  - 'web-ui'\n\nonlyBuiltDependencies:\n  - esbuild\n`;

  it('parses the block-sequence form (bare + quoted entries)', () => {
    expect(parseWorkspaceGlobs(BLOCK)).toEqual(['packages/*', 'cli', 'web-ui']);
  });

  it('stops at the next column-0 key (does not bleed into onlyBuiltDependencies)', () => {
    expect(parseWorkspaceGlobs(BLOCK)).not.toContain('esbuild');
  });

  it('normalizes CRLF so no glob trails a \\r (Windows core.autocrlf)', () => {
    const crlf = BLOCK.replace(/\n/g, '\r\n');
    expect(parseWorkspaceGlobs(crlf)).toEqual(['packages/*', 'cli', 'web-ui']);
  });

  it('tolerates whole-line and inline comments inside the block', () => {
    const withComments =
      'packages:\n' +
      '  # first the libraries\n' +
      "  - 'packages/*'\n" +
      "  - 'cli'  # the CLI root\n" +
      "  - 'web-ui'\n";
    expect(parseWorkspaceGlobs(withComments)).toEqual(['packages/*', 'cli', 'web-ui']);
  });

  it('tolerates blank lines interspersed between entries', () => {
    const withBlanks = "packages:\n  - 'packages/*'\n\n  - 'cli'\n";
    expect(parseWorkspaceGlobs(withBlanks)).toEqual(['packages/*', 'cli']);
  });

  it('accepts double-quoted, single-quoted, and bare scalars alike', () => {
    const mixed = 'packages:\n  - "packages/*"\n  - \'cli\'\n  - web-ui\n';
    expect(parseWorkspaceGlobs(mixed)).toEqual(['packages/*', 'cli', 'web-ui']);
  });

  it('is unaffected by the order of top-level keys', () => {
    const reordered = "onlyBuiltDependencies:\n  - esbuild\npackages:\n  - 'packages/*'\n";
    expect(parseWorkspaceGlobs(reordered)).toEqual(['packages/*']);
  });

  it('returns [] for flow style rather than silently mis-parsing (vacuous-pass guard then trips)', () => {
    expect(parseWorkspaceGlobs("packages: ['packages/*', 'cli']\n")).toEqual([]);
  });

  it('returns [] when there is no packages block at all', () => {
    expect(parseWorkspaceGlobs('onlyBuiltDependencies:\n  - esbuild\n')).toEqual([]);
  });
});

// --- Behavioral guard: each config actually enforces the ban -----------------

// A representative sample of the Node core network builtins the ban must cover.
// NETWORK_SNIPPET proves `no-restricted-imports` fires via the `axios` npm client
// only — a config that redeclared the rule and kept `axios` while dropping the
// `node:*` modules would still pass that check. Probing these directly asserts
// the denylist stays COMPLETE through per-package composition, not just that the
// rule fires on something. `node:net` is excluded: cli opts it out in dashboard.ts.
const NETWORK_CORE_MODULES = ['node:http', 'node:https', 'node:dgram', 'node:tls'];

describe('effective per-package config (composition / last-wins)', () => {
  /** @type {Map<string, Record<string, import('eslint').Linter.RuleEntry>>} configRel -> resolved network rules */
  const rulesByConfig = new Map();

  beforeAll(async () => {
    for (const configRel of CONFIG_FILES) {
      const pkgDir = join(REPO_ROOT, dirname(configRel));
      // Probe at a path the package actually ships code under (web-ui uses app/),
      // so a config that scopes the ban to its real source dir is exercised. The
      // path need not exist — config is computed, not parsed.
      rulesByConfig.set(configRel, await resolveNetworkRules(pkgDir, probeRelPath(pkgDir)));
    }
  }, RESOLVE_TIMEOUT_MS);

  it('resolved a config for every guarded package (no behavioral gap)', () => {
    // The structural guard guarantees every guarded package ships a config;
    // pin that the behavioral suite actually resolved one for each, so a package
    // can never be present-but-unverified.
    expect(CONFIG_FILES.length).toBe(GUARDED_PACKAGES.length);
  });

  it.each(CONFIG_FILES)('bans every network form in %s', (configRel) => {
    const fired = firedRuleIds(NETWORK_SNIPPET, rulesByConfig.get(configRel));
    for (const key of KEYS) {
      expect(fired, `${configRel} :: ${key}`).toContain(key);
    }
  });

  it.each(CONFIG_FILES)(
    'bans the node:* core network modules in %s (denylist stays complete)',
    (configRel) => {
      const rules = rulesByConfig.get(configRel);
      for (const mod of NETWORK_CORE_MODULES) {
        expect(firedRuleIds(`import m from '${mod}';`, rules), `${configRel} :: ${mod}`).toContain(
          'no-restricted-imports',
        );
      }
    },
  );
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
