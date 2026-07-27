import { execFileSync } from 'node:child_process';
import { existsSync, globSync, readFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ESLint, Linter } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

// This file guards the per-package ESLint configs two ways.
//
//  1. STRUCTURAL: every workspace package — enumerated from pnpm-workspace.yaml,
//     not a hand-maintained glob — must ship an eslint.config.mjs that extends
//     `@akasecurity/eslint-config`, must have a `lint` script that actually runs
//     eslint over its source dirs, and must ship an eslint.scripts.config.mjs if
//     it has a scripts/ dir. A package missing any of these is invisible to
//     `pnpm lint` and to a glob that only ever matched existing config files, so
//     it would ship UNGUARDED for network calls with CI green. Enumerating from
//     the manifest and pinning the result as an EXACT set catches a package that
//     was never in a config glob's universe.
//
//  2. BEHAVIORAL: resolve each real config through ESLint and assert the network
//     rules still fire on real code. Flat config resolves "last wins": the final
//     block matching a file overrides earlier ones for a given rule, and
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
      'Defines the shared config. Its `lint` script is a deliberate no-op, so requiring a config ' +
      'that eslint is never pointed at would assert nothing.',
  },
];
const OPT_OUT_NAMES = new Set(CONFIG_OPT_OUT.map((o) => o.name));

// Directories a package may ship lintable code under. Used both to pick the
// behavioral probe paths and to check the `lint` script names every one of them.
const SOURCE_DIRS = /** @type {const} */ (['src', 'app']);
const LINT_TARGET_DIRS = /** @type {const} */ (['src', 'app', 'test']);

// Every path git tracks, used to tell hand-written source from build output. A
// scripts/ dir on disk is not necessarily source: the plugin's build emits its
// bundled hooks to scripts/ (declared in turbo.json `build.outputs` and ignored
// by git), and demanding a lint config for generated bundles would be wrong.
// Tracked-ness is the only reliable signal here, so this meta-test asks git
// rather than guessing from the directory listing.
const TRACKED_FILES = (() => {
  try {
    return new Set(
      execFileSync('git', ['ls-files'], { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 << 20 })
        .split('\n')
        .filter(Boolean),
    );
  } catch (cause) {
    throw new Error(
      'Could not list tracked files with `git ls-files`. This suite audits the real workspace ' +
        'layout, so it must run inside a git checkout.',
      { cause },
    );
  }
})();

/** Whether `<dir>/<sub>` holds at least one git-tracked file (i.e. real source). */
const hasTrackedSource = (dir, sub) => {
  const prefix = `${dir}/${sub}/`;
  for (const f of TRACKED_FILES) if (f.startsWith(prefix)) return true;
  return false;
};

/**
 * Strip line and block comments so a commented-out import is not mistaken for a
 * live one. Without this, `// import { base } from '@akasecurity/eslint-config'`
 * satisfies the "extends" check and the structural guard reports nothing, leaving
 * the behavioral suite to report it as "the ban does not fire" — which sends the
 * reader hunting a composition bug instead of a missing import.
 * @param {string} source
 */
function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

// "Extends `@akasecurity/eslint-config`" = imports it (the root entry or the
// `/react` sub-entry) via `import ... from` or `require(...)`. This is the fast,
// readable statement of intent; the BEHAVIORAL suite is what proves the import
// wires the network rules, so a config that imports the package but forgets to
// spread `...base` is caught there, not here.
const IMPORTS_SHARED_CONFIG =
  /(?:import[^;]*from[ \t]*|require\([ \t]*)['"]@akasecurity\/eslint-config(?:\/[\w.-]+)?['"]/;

/** Whether a config file's live (non-comment) source imports the shared config. */
const extendsSharedConfig = (abs) =>
  IMPORTS_SHARED_CONFIG.test(stripComments(readFileSync(abs, 'utf8')));

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
 * a silent under-enumeration. An exclusion glob throws for the same reason:
 * globSync would treat `!pkg` as a literal pattern that matches nothing, leaving
 * the excluded directory in the enumeration under a misleading failure.
 * @param {string} rawYaml
 * @returns {string[]}
 */
function parseWorkspaceGlobs(rawYaml) {
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
    if (!m) continue;
    const glob = m[1].trim();
    if (glob.startsWith('!')) {
      throw new Error(
        `pnpm-workspace.yaml declares the exclusion glob "${glob}", which this parser does not ` +
          'model. Teach parseWorkspaceGlobs/discoverWorkspacePackages to honour negation before ' +
          'relying on the enumeration.',
      );
    }
    globs.push(glob);
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
 * glob and keep the directories that hold a package.json. `label` is what every
 * failure message prints — a package.json may legally omit `name`, and a bare
 * `undefined` in a violation list tells the reader nothing about which directory
 * to fix.
 * @returns {{
 *   name: string, dir: string, label: string, lintScript: string,
 *   configRel: string, hasConfig: boolean, extendsShared: boolean,
 *   sourceDirs: string[], hasScriptsDir: boolean,
 *   scriptsConfigRel: string, hasScriptsConfig: boolean, scriptsExtendsShared: boolean,
 * }[]}
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
    // git reports posix paths on every platform; globSync yields native ones.
    const posixDir = dir.split(sep).join('/');
    const pkg = JSON.parse(readFileSync(join(REPO_ROOT, dir, 'package.json'), 'utf8'));
    const name = typeof pkg.name === 'string' && pkg.name ? pkg.name : posixDir;
    const configRel = join(dir, 'eslint.config.mjs');
    const configAbs = join(REPO_ROOT, configRel);
    const hasConfig = existsSync(configAbs);
    const scriptsConfigRel = join(dir, 'eslint.scripts.config.mjs');
    const scriptsConfigAbs = join(REPO_ROOT, scriptsConfigRel);
    const hasScriptsConfig = existsSync(scriptsConfigAbs);
    return {
      name,
      dir,
      label: name === posixDir ? posixDir : `${name} (${posixDir})`,
      lintScript: pkg.scripts?.lint ?? '',
      configRel,
      hasConfig,
      extendsShared: hasConfig && extendsSharedConfig(configAbs),
      // Tracked source only — a dir that exists purely as build output is not
      // something lint should be pointed at.
      sourceDirs: SOURCE_DIRS.filter((d) => hasTrackedSource(posixDir, d)),
      lintTargetDirs: LINT_TARGET_DIRS.filter((d) => hasTrackedSource(posixDir, d)),
      hasScriptsDir: hasTrackedSource(posixDir, 'scripts'),
      scriptsConfigRel,
      hasScriptsConfig,
      scriptsExtendsShared: hasScriptsConfig && extendsSharedConfig(scriptsConfigAbs),
    };
  });
}

const WORKSPACE_PACKAGES = discoverWorkspacePackages();

// The exact set of workspace packages expected on disk, pinned by name (sorted).
// This is the drift guard for the enumeration: a hand-rolled pnpm-workspace.yaml
// parse that silently dropped ONE package would still clear a `>=` floor, and no
// derived-vs-derived equality can catch it either (a package absent from
// discovery is absent from both sides). An exact set fails loudly on any add /
// drop / rename.
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
 * @param {ReturnType<typeof discoverWorkspacePackages>} guarded
 */
function configViolations(guarded) {
  return {
    missing: guarded.filter((p) => !p.hasConfig).map((p) => p.label),
    notExtending: guarded.filter((p) => p.hasConfig && !p.extendsShared).map((p) => p.label),
    // A config eslint is never pointed at enforces nothing: `pnpm lint` is
    // `turbo run lint`, and turbo SKIPS a package with no `lint` script (exit 0,
    // "No tasks were executed"). The script must also name every source dir the
    // package actually ships, or those files go unlinted by construction.
    lintNotWired: guarded
      .filter(
        (p) =>
          !/\beslint\b/.test(p.lintScript) ||
          (p.lintTargetDirs ?? []).some((d) => !new RegExp(`\\b${d}\\b`).test(p.lintScript)),
      )
      .map((p) => p.label),
    // `eslint <src> <test>` never reaches scripts/, so a scripts/ dir needs its
    // own network-guard config (run with --no-config-lookup as a second pass).
    missingScriptsConfig: guarded
      .filter((p) => p.hasScriptsDir && !p.hasScriptsConfig)
      .map((p) => p.label),
    scriptsNotExtending: guarded
      .filter((p) => p.hasScriptsConfig && !p.scriptsExtendsShared)
      .map((p) => p.label),
  };
}

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

// Every module specifier the shared ban lists, probed individually. NETWORK_SNIPPET
// only proves `no-restricted-imports` fires via `axios`, so a composition that
// redeclared the rule and narrowed its module list — keeping the npm clients while
// dropping the node builtins, or keeping the `node:` forms while dropping the bare
// ones — would still pass it. The bare specifiers matter most: they are the
// documented bypass the shared config lists both forms to close.
const NETWORK_MODULE_PROBES = [
  'node:http',
  'http',
  'node:https',
  'https',
  'node:http2',
  'http2',
  'node:net',
  'net',
  'node:dgram',
  'dgram',
  'node:tls',
  'tls',
  'node:dns',
  'dns',
  'node:dns/promises',
  'dns/promises',
  'axios',
  'undici',
  'got',
  'node-fetch',
  // A deep import into an npm client, closed by the `<client>/*` pattern ban.
  'axios/lib/adapters/http.js',
];

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
 * Resolve the effective config a package's real config produces for `relFile`,
 * and return just the four network rules from it. calculateConfigForFile runs the
 * full flat-config cascade without parsing the file, so it needs no type
 * information and the probe path need not exist. Passing `configName` explicitly
 * is what `--no-config-lookup -c eslint.scripts.config.mjs` does in the lint
 * script: resolve against that config alone.
 * @param {string} pkgDir absolute package directory
 * @param {string} relFile path within the package to resolve config for
 * @param {string} configName the config file to resolve against
 */
async function resolveNetworkRules(pkgDir, relFile, configName = 'eslint.config.mjs') {
  const eslint = new ESLint({ cwd: pkgDir, overrideConfigFile: join(pkgDir, configName) });
  const config = await eslint.calculateConfigForFile(join(pkgDir, relFile));
  return Object.fromEntries(KEYS.map((k) => [k, config.rules?.[k]]));
}

/** Which network rule ids fire when `code` is linted with `rules`. */
function firedRuleIds(code, rules) {
  return new Set(linter.verify(code, { languageOptions: LANG, rules }).map((m) => m.ruleId));
}

const importOf = (specifier) => `import probe from ${JSON.stringify(specifier)};`;

// Every (config, path) pair the behavioral suite resolves. A package is probed in
// EVERY source dir it ships, not just the first match: web-ui ships app/ and no
// src/, and a package could ship both, so picking one dir would leave a
// path-scoped block unexercised — the last-wins mistake this suite exists to
// catch. Packages with a scripts/ dir contribute their scripts config too.
const PROBE_TARGETS = GUARDED_PACKAGES.flatMap((p) => {
  const targets = p.hasConfig
    ? (p.sourceDirs.length ? p.sourceDirs : ['src']).map((d) => ({
        id: `${p.configRel} @ ${d}/`,
        pkgDir: join(REPO_ROOT, p.dir),
        configName: 'eslint.config.mjs',
        relFile: `${d}/__network_ban_probe__.ts`,
      }))
    : [];
  if (p.hasScriptsConfig) {
    targets.push({
      id: `${p.scriptsConfigRel} @ scripts/`,
      pkgDir: join(REPO_ROOT, p.dir),
      configName: 'eslint.scripts.config.mjs',
      relFile: 'scripts/__network_ban_probe__.mjs',
    });
  }
  return targets;
});

// --- Structural guard: every package ships a network-guarded config ----------

describe('every workspace package ships a network-guarded eslint config', () => {
  it('enumerates exactly the expected workspace packages (drift guard)', () => {
    // The explicit `workspaceGlobs()` check keeps the failure legible when the
    // parser is the culprit (empty ⇒ manifest reformatted / flow-style).
    expect(workspaceGlobs().length, 'pnpm-workspace.yaml parsed to zero globs').toBeGreaterThan(0);
    const found = [...WORKSPACE_PACKAGES.map((p) => p.name)].sort();
    const expected = [...EXPECTED_WORKSPACE_PACKAGE_NAMES].sort();
    expect(
      found,
      'The set of workspace packages changed. If a package was added or renamed, update ' +
        'EXPECTED_WORKSPACE_PACKAGE_NAMES here AND make sure the package ships an ' +
        'eslint.config.mjs extending @akasecurity/eslint-config plus a `lint` script that runs ' +
        'eslint over its source dirs (see CLAUDE.md "Adding a new workspace package"). If nothing ' +
        'was added, the pnpm-workspace.yaml parse has regressed and packages are silently missing ' +
        'from the guard.',
    ).toEqual(expected);
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

  it('every guarded package has a lint script that runs eslint over its source dirs', () => {
    const { lintNotWired } = configViolations(GUARDED_PACKAGES);
    expect(
      lintNotWired,
      lintNotWired.length
        ? 'A config file only enforces the ban if eslint is pointed at the package. `pnpm lint` is ' +
            '`turbo run lint`, which SKIPS a package with no `lint` script (exit 0, "No tasks were ' +
            'executed"), so these packages ship an unenforced config. Add a `lint` script that runs ' +
            `eslint over every source dir the package ships:\n  ${lintNotWired.join('\n  ')}`
        : undefined,
    ).toEqual([]);
  });

  it('every package with a scripts/ dir ships a network-guarded scripts config', () => {
    const { missingScriptsConfig, scriptsNotExtending } = configViolations(GUARDED_PACKAGES);
    expect(
      missingScriptsConfig,
      missingScriptsConfig.length
        ? 'These packages have a scripts/ dir that `eslint src test` never reaches, and no ' +
            'eslint.scripts.config.mjs to cover it — so their dev/CI scripts are unguarded for ' +
            'network calls. Add one (see cli/eslint.scripts.config.mjs) and a second lint pass: ' +
            `eslint --no-config-lookup -c eslint.scripts.config.mjs scripts:\n  ${missingScriptsConfig.join('\n  ')}`
        : undefined,
    ).toEqual([]);
    expect(
      scriptsNotExtending,
      scriptsNotExtending.length
        ? 'These eslint.scripts.config.mjs files never import @akasecurity/eslint-config, so they ' +
            `do not wire the shared network guard (spread ...networkGuard):\n  ${scriptsNotExtending.join('\n  ')}`
        : undefined,
    ).toEqual([]);
  });
});

describe('CONFIG_OPT_OUT hygiene', () => {
  const names = new Set(WORKSPACE_PACKAGES.map((p) => p.name));

  it.each(CONFIG_OPT_OUT)('$name is a real workspace package with a reason', ({ name, reason }) => {
    expect(names).toContain(name);
    // The reason is the whole point of the list — an entry without one is an
    // undocumented hole in the no-network enforcement.
    expect(reason?.trim(), `${name} has no reason`).toBeTruthy();
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
  // it. Exercise them directly to prove the guard fails LOUDLY and NAMES every
  // offending package.
  /** @param {object} over */
  const pkg = (over) => ({
    name: '@akasecurity/newpkg',
    dir: 'packages/newpkg',
    label: '@akasecurity/newpkg (packages/newpkg)',
    lintScript: 'eslint src test',
    hasConfig: true,
    extendsShared: true,
    sourceDirs: ['src'],
    lintTargetDirs: ['src', 'test'],
    hasScriptsDir: false,
    hasScriptsConfig: false,
    scriptsExtendsShared: false,
    ...over,
  });

  it('names a package that ships no config', () => {
    const v = configViolations([pkg({ hasConfig: false, extendsShared: false })]);
    expect(v.missing).toEqual(['@akasecurity/newpkg (packages/newpkg)']);
    expect(v.notExtending).toEqual([]);
  });

  it('names a package whose config does not extend the shared config', () => {
    const v = configViolations([pkg({ extendsShared: false })]);
    expect(v.notExtending).toEqual(['@akasecurity/newpkg (packages/newpkg)']);
    expect(v.missing).toEqual([]);
  });

  it('names a package with no lint script (turbo would skip it silently)', () => {
    const v = configViolations([pkg({ lintScript: '' })]);
    expect(v.lintNotWired).toEqual(['@akasecurity/newpkg (packages/newpkg)']);
  });

  it('names a package whose lint script does not invoke eslint', () => {
    const v = configViolations([pkg({ lintScript: "echo 'no self-lint'" })]);
    expect(v.lintNotWired).toEqual(['@akasecurity/newpkg (packages/newpkg)']);
  });

  it('names a package with a scripts/ dir and no scripts config', () => {
    const v = configViolations([pkg({ hasScriptsDir: true, hasScriptsConfig: false })]);
    expect(v.missingScriptsConfig).toEqual(['@akasecurity/newpkg (packages/newpkg)']);
  });

  it('names a scripts config that does not extend the shared config', () => {
    const v = configViolations([
      pkg({ hasScriptsDir: true, hasScriptsConfig: true, scriptsExtendsShared: false }),
    ]);
    expect(v.scriptsNotExtending).toEqual(['@akasecurity/newpkg (packages/newpkg)']);
  });

  it('falls back to the directory when package.json omits a name', () => {
    const v = configViolations([
      pkg({ name: 'packages/anon', label: 'packages/anon', hasConfig: false }),
    ]);
    expect(v.missing).toEqual(['packages/anon']);
  });

  it('clears a healthy package', () => {
    const v = configViolations([pkg({})]);
    expect(v).toEqual({
      missing: [],
      notExtending: [],
      lintNotWired: [],
      missingScriptsConfig: [],
      scriptsNotExtending: [],
    });
  });

  it('reports every offender in a mixed set (fails loudly, not on the first)', () => {
    const v = configViolations([
      pkg({ name: 'a', label: 'a', hasConfig: false, extendsShared: false }),
      pkg({ name: 'b', label: 'b' }),
      pkg({ name: 'c', label: 'c', extendsShared: false }),
      pkg({ name: 'd', label: 'd', hasConfig: false, extendsShared: false }),
    ]);
    expect(v.missing).toEqual(['a', 'd']);
    expect(v.notExtending).toEqual(['c']);
  });
});

describe('the config-file checks (tested on synthetic source)', () => {
  it('does not mistake a commented-out import for extending the shared config', () => {
    const commented = "// import { base } from '@akasecurity/eslint-config';\nexport default [];\n";
    expect(IMPORTS_SHARED_CONFIG.test(stripComments(commented))).toBe(false);
    const blockCommented =
      "/* import { base } from '@akasecurity/eslint-config'; */\nexport default [];\n";
    expect(IMPORTS_SHARED_CONFIG.test(stripComments(blockCommented))).toBe(false);
  });

  it('still recognises a live import (root entry, /react sub-entry, require)', () => {
    for (const src of [
      "import { base } from '@akasecurity/eslint-config';",
      "import { react } from '@akasecurity/eslint-config/react';",
      "const { base } = require('@akasecurity/eslint-config');",
    ]) {
      expect(IMPORTS_SHARED_CONFIG.test(stripComments(src)), src).toBe(true);
    }
  });

  it('does not strip a URL inside a live import', () => {
    const src = "import { base } from '@akasecurity/eslint-config'; // see https://example.com";
    expect(IMPORTS_SHARED_CONFIG.test(stripComments(src))).toBe(true);
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

  it('throws on an exclusion glob rather than silently over-including', () => {
    // globSync treats `!packages/legacy` as a literal pattern matching nothing,
    // so the excluded dir would stay in the enumeration and surface as a
    // confusing EXPECTED_WORKSPACE_PACKAGE_NAMES diff.
    expect(() =>
      parseWorkspaceGlobs("packages:\n  - 'packages/*'\n  - '!packages/legacy'\n"),
    ).toThrow(/exclusion glob/);
  });

  it('returns [] for flow style rather than silently mis-parsing (vacuous-pass guard then trips)', () => {
    expect(parseWorkspaceGlobs("packages: ['packages/*', 'cli']\n")).toEqual([]);
  });

  it('returns [] when there is no packages block at all', () => {
    expect(parseWorkspaceGlobs('onlyBuiltDependencies:\n  - esbuild\n')).toEqual([]);
  });
});

// --- Behavioral guard: each config actually enforces the ban -----------------

describe('effective per-package config (composition / last-wins)', () => {
  /** @type {Map<string, Record<string, import('eslint').Linter.RuleEntry>>} */
  const rulesById = new Map();

  beforeAll(async () => {
    for (const t of PROBE_TARGETS) {
      rulesById.set(t.id, await resolveNetworkRules(t.pkgDir, t.relFile, t.configName));
    }
  }, RESOLVE_TIMEOUT_MS);

  it('resolved rules for every probe target (no behavioral gap)', () => {
    // Asserts the thing that can genuinely be short: a resolution that threw or
    // was skipped leaves the map smaller than the target list.
    expect(rulesById.size).toBe(PROBE_TARGETS.length);
    expect(PROBE_TARGETS.length).toBeGreaterThanOrEqual(GUARDED_PACKAGES.length);
  });

  it.each(PROBE_TARGETS.map((t) => t.id))('bans every network form in %s', (id) => {
    const fired = firedRuleIds(NETWORK_SNIPPET, rulesById.get(id));
    for (const key of KEYS) {
      expect(fired, `${id} :: ${key}`).toContain(key);
    }
  });

  it.each(PROBE_TARGETS.map((t) => t.id))('bans every listed module in %s', (id) => {
    const rules = rulesById.get(id);
    for (const mod of NETWORK_MODULE_PROBES) {
      expect(firedRuleIds(importOf(mod), rules), `${id} :: ${mod}`).toContain(
        'no-restricted-imports',
      );
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

describe('cli scripts-config file-scoped opt-out (real config)', () => {
  const cliDir = join(REPO_ROOT, 'cli');
  const CONFIG = 'eslint.scripts.config.mjs';
  const resolved = { smoke: undefined, otherScript: undefined };

  beforeAll(async () => {
    resolved.smoke = await resolveNetworkRules(cliDir, 'scripts/smoke-dashboard.mjs', CONFIG);
    resolved.otherScript = await resolveNetworkRules(cliDir, 'scripts/__other__.mjs', CONFIG);
  }, RESOLVE_TIMEOUT_MS);

  it('allows node:http in smoke-dashboard.mjs (the loopback health check)', () => {
    expect(firedRuleIds(importOf('node:http'), resolved.smoke).size).toBe(0);
    expect(firedRuleIds("await import('node:http');", resolved.smoke).size).toBe(0);
  });

  it('still bans every OTHER network module in smoke-dashboard.mjs', () => {
    expect(firedRuleIds(importOf('node:https'), resolved.smoke)).toContain('no-restricted-imports');
    expect(firedRuleIds("fetch('/x');", resolved.smoke)).toContain('no-restricted-globals');
  });

  it('does NOT leak the node:http opt-out to other cli scripts', () => {
    expect(firedRuleIds(importOf('node:http'), resolved.otherScript)).toContain(
      'no-restricted-imports',
    );
  });
});
