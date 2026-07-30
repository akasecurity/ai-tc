import { execFileSync } from 'node:child_process';
import { existsSync, globSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, posix, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ESLint, Linter } from 'eslint';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

// This file guards the per-package ESLint configs three ways.
//
//  1. STRUCTURAL: every workspace package — enumerated from pnpm-workspace.yaml,
//     not a hand-maintained glob — must ship an eslint.config.mjs that extends
//     `@akasecurity/eslint-config`, must have a `lint` script that points eslint
//     at every directory it ships code in AND at every lintable file sitting
//     directly in its root, and must ship an eslint.scripts.config.mjs if it
//     ships a scripts/ dir. A package missing any of these is invisible to
//     `pnpm lint` and to a glob that only ever matched existing config files, so
//     it would ship UNGUARDED for network calls with CI green. The package set,
//     each package's code directories and each package's top-level files are all
//     DERIVED (from the manifest and from git-tracked lintable files), so a new
//     package — or an existing one growing a new source dir or a new root config
//     file — cannot fall outside the guard without the pinned expectations
//     failing loudly.
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
//  3. FAULT INJECTION: run the real linter over real paths with network code
//     planted in them. (1) and (2) both reason about configuration; neither
//     parses a file. A root config file sits outside its package's tsconfig
//     `include`, so the type-aware parser rejects it outright ("was not found by
//     the project service") unless the config drops the type-aware rules for
//     that path — and a file that fails to parse reports NO rule violations, so
//     the ban would be structurally wired, behaviorally correct, and enforcing
//     nothing. Only running the linter shows that.
//
// The three compose into a closed loop: (1) guarantees every package ships a
// config and points eslint at everything it ships, (2) is fed the same derived
// list and proves each config enforces the ban, (3) proves the files the ban
// covers actually parse and report. A new package that forgets its config fails
// (1); one whose config fails to wire the ban fails (2); one whose root files
// cannot be linted at all fails (3).

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

// The extensions ESLint actually lints here. This is what separates a code
// directory from a data one: packages/schema/drizzle holds only .sql/.json
// migrations, so there is nothing there for the ban to guard, while
// plugins/claude-code/eval ships a real .ts file and belongs behind it.
const LINTABLE_EXT = /\.[cm]?[jt]sx?$/;

// Which directories hold code is DERIVED per package, never hardcoded. A fixed
// ['src', 'app', 'test'] list would be the same hand-maintained hole this file
// exists to close, one level down: a package putting source in lib/ or eval/
// would clear every assertion below while shipping unguarded. Tracked-ness is
// also what separates source from build output — the plugin's build emits
// bundled hooks into scripts/ (declared in turbo.json `build.outputs`, ignored
// by git), and demanding a lint config for generated bundles would be wrong.
//
// Indexed once from one `git ls-files` walk into two maps, so each lookup is
// O(1) instead of a scan over every path:
//
//   childDirs — parent dir -> immediate child dirs holding a lintable tracked
//     file at any depth. This is the bucket `eslint src test` satisfies.
//   rootFiles — parent dir -> lintable tracked files sitting DIRECTLY in it.
//     A separate bucket because a root file has no directory segment to index:
//     it can never appear in childDirs, so widening the source-dir check can
//     never reach it, and every package keeps its build and tooling config
//     (tsup.config.ts, vitest.config.ts, eslint.config.mjs) exactly there.
const LINTABLE_TRACKED = (() => {
  let tracked;
  try {
    tracked = execFileSync('git', ['ls-files'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      maxBuffer: 64 << 20,
    }).split('\n');
  } catch (cause) {
    throw new Error(
      'Could not list tracked files with `git ls-files`. This suite audits the real workspace ' +
        'layout, so it must run inside a git checkout.',
      { cause },
    );
  }
  /** @type {Map<string, Set<string>>} */
  const childDirs = new Map();
  /** @type {Map<string, Set<string>>} */
  const rootFiles = new Map();
  for (const file of tracked) {
    if (!file || !LINTABLE_EXT.test(file)) continue;
    const parts = file.split('/');
    const parent = parts.slice(0, -1).join('/');
    let siblings = rootFiles.get(parent);
    if (!siblings) rootFiles.set(parent, (siblings = new Set()));
    siblings.add(/** @type {string} */ (parts.at(-1)));
    for (let i = 0; i < parts.length - 1; i++) {
      const ancestor = parts.slice(0, i).join('/');
      let children = childDirs.get(ancestor);
      if (!children) childDirs.set(ancestor, (children = new Set()));
      children.add(/** @type {string} */ (parts[i]));
    }
  }
  return { childDirs, rootFiles };
})();

/** The immediate subdirectories of `dir` that hold lintable tracked source. */
const lintableChildDirs = (dir) => [...(LINTABLE_TRACKED.childDirs.get(dir) ?? [])].sort();

/** The lintable tracked files sitting directly in `dir`, no subdirectory. */
const lintableRootFiles = (dir) => [...(LINTABLE_TRACKED.rootFiles.get(dir) ?? [])].sort();

// Scripts live behind a SEPARATE second lint pass (`--no-config-lookup -c
// eslint.scripts.config.mjs scripts`), so they are excluded from the main
// config's probe set and handled by their own structural check.
const SCRIPTS_DIR = 'scripts';

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
 *   codeDirs: string[], sourceDirs: string[], rootFiles: string[], hasScriptsDir: boolean,
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
    const codeDirs = lintableChildDirs(posixDir);
    return {
      name,
      dir,
      label: name === posixDir ? posixDir : `${name} (${posixDir})`,
      lintScript: pkg.scripts?.lint ?? '',
      configRel,
      hasConfig,
      extendsShared: hasConfig && extendsSharedConfig(configAbs),
      // Derived, not hardcoded: every child dir holding lintable tracked source.
      // `codeDirs` is what the lint script must cover (scripts/ included — its
      // second pass is an eslint invocation too); `sourceDirs` is what the MAIN
      // config is probed at, so scripts/ drops out.
      codeDirs,
      sourceDirs: codeDirs.filter((d) => d !== SCRIPTS_DIR),
      // The other half of what the lint script must cover, derived the same way.
      rootFiles: lintableRootFiles(posixDir),
      hasScriptsDir: codeDirs.includes(SCRIPTS_DIR),
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
  '@akasecurity/audit-gate',
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

// eslint flags that consume the NEXT argument, so its value is not mistaken for
// a lint target (`-c eslint.scripts.config.mjs scripts` targets scripts, not the
// config file). Boolean flags are skipped by the leading-dash test alone.
const ESLINT_VALUE_FLAGS = new Set([
  '-c',
  '--config',
  '--ext',
  '--rulesdir',
  '--plugin',
  '--rule',
  '--parser',
  '--parser-options',
  '--resolve-plugins-relative-to',
  '--ignore-pattern',
  '--ignore-path',
  '--format',
  '-f',
  '--output-file',
  '-o',
  '--max-warnings',
  '--global',
  '--flag',
  '--concurrency',
]);

const unquote = (token) => token.replace(/^['"]|['"]$/g, '');

/**
 * Every eslint invocation in a `lint` script, in order — its `-c`/`--config`
 * override (undefined when the invocation uses ordinary config lookup) and its
 * positional path targets. Kept as invocations rather than one flat target list
 * because the fault-injection run below has to reproduce ONE of them faithfully:
 * cli lints `src test *.config.*` under eslint.config.mjs and `scripts` under
 * eslint.scripts.config.mjs, so running the flattened target list under either
 * config lints half the package with the wrong ruleset. Only the `-c <file>`
 * form is read — the repo uses it everywhere, and `--config=<file>` falls
 * through as a plain flag, which costs the config override but never a target.
 * @param {string} lintScript
 * @returns {{ configName: string | undefined, targets: string[] }[]}
 */
function eslintInvocations(lintScript) {
  const invocations = [];
  for (const command of lintScript.split(/&&|\|\||;/)) {
    const tokens = command.match(/[^\s"']+|"[^"]*"|'[^']*'/g) ?? [];
    const start = tokens.findIndex((t) => /(?:^|\/)eslint$/.test(unquote(t)));
    if (start === -1) continue;
    /** @type {{ configName: string | undefined, targets: string[] }} */
    const invocation = { configName: undefined, targets: [] };
    for (let i = start + 1; i < tokens.length; i++) {
      const token = unquote(tokens[i]);
      if (token.startsWith('-')) {
        if (ESLINT_VALUE_FLAGS.has(token)) {
          const next = tokens[i + 1];
          if ((token === '-c' || token === '--config') && next !== undefined) {
            invocation.configName = unquote(next);
          }
          i++;
        }
        continue;
      }
      invocation.targets.push(token);
    }
    invocations.push(invocation);
  }
  return invocations;
}

/**
 * The positional path targets of every eslint invocation in a `lint` script.
 * Asserting on these rather than substring-matching the raw command string is
 * what makes the coverage check mean something: `eslint .` is broader than
 * `eslint src test` (a substring match wrongly rejects it), while
 * `eslint src/index.ts` lints one file (a substring match wrongly accepts it as
 * covering src/).
 * @param {string} lintScript
 * @returns {string[]}
 */
const eslintTargets = (lintScript) => eslintInvocations(lintScript).flatMap((i) => i.targets);

/**
 * Whether an eslint path target lints everything in `dir`. A target covers the
 * directory when it IS the directory, an ancestor of it, or `.`; a target that
 * merely points at a file inside it does not. A glob is reduced to its literal
 * prefix, so `src/**\/*.ts` still covers `src`.
 * @param {string} target
 * @param {string} dir
 */
function targetCoversDir(target, dir) {
  const normalized = target.replace(/^\.\//, '').replace(/\/+$/, '');
  if (normalized === '.' || normalized === '') return true;
  const globAt = normalized.search(/[*?[{]/);
  const base = (globAt === -1 ? normalized : normalized.slice(0, globAt)).replace(/\/+$/, '');
  if (base === '') return true;
  return dir === base || dir.startsWith(`${base}/`);
}

/**
 * Whether an eslint path target lints the package-relative file `file`. A target
 * covers it when it IS the file, when it is `.` or a directory the file sits
 * under, or when it is a glob the file matches.
 *
 * targetCoversDir's literal-prefix reduction is deliberately NOT reused: it
 * answers "could this target reach anything under that directory", and reduces
 * every leading-glob pattern to an empty prefix that covers everything. For a
 * file that is the wrong question — it would let `*.config.*` vacuously "cover"
 * middleware.ts, which is exactly the uncovered-root-file case this bucket
 * exists to catch. So the glob is matched against the filename for real, via
 * path.posix.matchesGlob so a Windows checkout answers identically. A pattern
 * the matcher rejects counts as NOT covering: the guard then names the file as
 * uncovered, which is the side to fail on.
 * @param {string} target
 * @param {string} file package-relative posix path
 */
function targetCoversFile(target, file) {
  const normalized = target.replace(/^\.\//, '').replace(/\/+$/, '');
  if (normalized === '.' || normalized === '') return true;
  if (normalized === file) return true;
  if (file.startsWith(`${normalized}/`)) return true;
  try {
    return posix.matchesGlob(file, normalized);
  } catch {
    return false;
  }
}

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
      .filter((p) => {
        const targets = eslintTargets(p.lintScript);
        if (!targets.length) return true;
        return (p.codeDirs ?? []).some((d) => !targets.some((t) => targetCoversDir(t, d)));
      })
      .map((p) => p.label),
    // Top-level files are their own bucket, and the reason is structural rather
    // than an oversight: a file sitting directly in a package root contributes
    // no directory segment, so it can never enter codeDirs and the check above
    // cannot see it however the source dirs are widened. Every package keeps its
    // build and tooling config there, which is shipped OSS source — a `fetch()`
    // in tsup.config.ts is exactly the thing the workspace ban exists to stop.
    // Each offender names its uncovered files, because "add a target" is not
    // actionable without knowing which ones are missing.
    rootFilesNotWired: guarded.flatMap((p) => {
      const targets = eslintTargets(p.lintScript);
      const uncovered = (p.rootFiles ?? []).filter(
        (f) => !targets.some((t) => targetCoversFile(t, f)),
      );
      return uncovered.length ? [`${p.label} → ${uncovered.join(', ')}`] : [];
    }),
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
async function resolveConfig(pkgDir, relFile, configName = 'eslint.config.mjs') {
  const eslint = new ESLint({ cwd: pkgDir, overrideConfigFile: join(pkgDir, configName) });
  const config = await eslint.calculateConfigForFile(join(pkgDir, relFile));
  if (!config) {
    // calculateConfigForFile yields undefined when no block matches the path —
    // the "imports the shared config but never spreads it" case. Reported as
    // that, rather than crashing the suite on a property of undefined.
    throw new Error(
      'ESLint resolved no config block for this path. The config most likely imports ' +
        '@akasecurity/eslint-config without spreading it (…base / …react / …networkGuard).',
    );
  }
  return config;
}

/** Just the four network rules out of a resolved config. */
const networkRulesOf = (config) => Object.fromEntries(KEYS.map((k) => [k, config?.rules?.[k]]));

/** A rule's resolved severity, normalized out of the `[severity, …options]` form. */
const severityOf = (config, ruleId) => {
  const entry = config?.rules?.[ruleId];
  return Array.isArray(entry) ? entry[0] : entry;
};

/** Resolve a config and return only its four network rules. */
async function resolveNetworkRules(pkgDir, relFile, configName = 'eslint.config.mjs') {
  return networkRulesOf(await resolveConfig(pkgDir, relFile, configName));
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
  const pkgDir = join(REPO_ROOT, p.dir);
  const targets = p.hasConfig
    ? (p.sourceDirs.length ? p.sourceDirs : ['src']).map((d) => ({
        id: `${p.configRel} @ ${d}/`,
        pkgDir,
        configName: 'eslint.config.mjs',
        relFile: `${d}/__network_ban_probe__.ts`,
      }))
    : [];
  // Top-level files are probed at their REAL paths, never a synthetic name.
  // Which config block claims a root file depends on its filename — the build
  // and tooling config resolves through `rootConfigFiles` with the type-aware
  // rules off, while web-ui's middleware.ts keeps them — so an invented name
  // would exercise a block that no real file resolves to.
  if (p.hasConfig) {
    for (const file of p.rootFiles) {
      targets.push({
        id: `${p.configRel} @ ${file}`,
        pkgDir,
        configName: 'eslint.config.mjs',
        relFile: file,
      });
    }
  }
  if (p.hasScriptsConfig) {
    targets.push({
      id: `${p.scriptsConfigRel} @ scripts/`,
      pkgDir,
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

  it('every guarded package has a lint script covering every dir it ships code in', () => {
    const { lintNotWired } = configViolations(GUARDED_PACKAGES);
    expect(
      lintNotWired,
      lintNotWired.length
        ? 'A config file only enforces the ban if eslint is pointed at the code. `pnpm lint` is ' +
            '`turbo run lint`, which SKIPS a package with no `lint` script (exit 0, "No tasks were ' +
            'executed"), and a script that lists only some directories leaves the rest unlinted. ' +
            'Point the `lint` script at every directory the package ships code in (a bare `.` ' +
            `counts; naming individual files does not):\n  ${lintNotWired.join('\n  ')}`
        : undefined,
    ).toEqual([]);
  });

  it('every guarded package has a lint script covering every top-level file it ships', () => {
    const { rootFilesNotWired } = configViolations(GUARDED_PACKAGES);
    expect(
      rootFilesNotWired,
      rootFilesNotWired.length
        ? 'These packages ship a lintable file directly in their root that no eslint invocation in ' +
            'their `lint` script targets. `eslint src test` can never reach one — a root file has no ' +
            'directory segment — so it is unlinted by construction and a `fetch()` there passes ' +
            '`pnpm lint` (CLAUDE.md "No network calls"). Add a target that covers it: `*.config.*` ' +
            "covers the build and tooling config, anything else is named explicitly (see web-ui's " +
            'middleware.ts). A root config file also sits outside the tsconfig `include`, so the ' +
            'package eslint config must spread `...rootConfigFiles` after its projectService block ' +
            `or the type-aware parser rejects the file instead of linting it:\n  ${rootFilesNotWired.join('\n  ')}`
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
    lintScript: 'eslint src test *.config.*',
    hasConfig: true,
    extendsShared: true,
    codeDirs: ['src', 'test'],
    sourceDirs: ['src'],
    rootFiles: ['vitest.config.ts'],
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

  it('names a package whose lint script misses a top-level file, and the file', () => {
    const v = configViolations([
      pkg({ lintScript: 'eslint src test', rootFiles: ['tsup.config.ts', 'vitest.config.ts'] }),
    ]);
    expect(v.rootFilesNotWired).toEqual([
      '@akasecurity/newpkg (packages/newpkg) → tsup.config.ts, vitest.config.ts',
    ]);
    // The source dirs ARE covered, so the codeDirs bucket sees nothing wrong.
    // That is the whole point of tracking root files separately.
    expect(v.lintNotWired).toEqual([]);
  });

  it('names only the top-level files a partial glob misses', () => {
    const v = configViolations([
      pkg({
        lintScript: 'eslint src test *.config.*',
        rootFiles: ['vitest.config.ts', 'setup.ts'],
      }),
    ]);
    expect(v.rootFilesNotWired).toEqual(['@akasecurity/newpkg (packages/newpkg) → setup.ts']);
  });

  it('clears a package whose lint script names its top-level files explicitly', () => {
    const v = configViolations([
      pkg({
        lintScript: 'eslint app middleware.ts test *.config.*',
        codeDirs: ['app', 'test'],
        sourceDirs: ['app', 'test'],
        rootFiles: ['middleware.ts', 'next.config.ts'],
      }),
    ]);
    expect(v.rootFilesNotWired).toEqual([]);
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
      rootFilesNotWired: [],
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

describe('eslintTargets / targetCoversDir / targetCoversFile (the lint-coverage check)', () => {
  // The predicate this replaces was a substring match on the command string,
  // which rejected a broader-and-correct `eslint .` and accepted
  // `eslint src/index.ts` as covering src/. Pin both directions.
  it('extracts the positional targets of every eslint invocation', () => {
    expect(eslintTargets('eslint src test')).toEqual(['src', 'test']);
    expect(
      eslintTargets(
        'eslint src test && eslint --no-config-lookup -c eslint.scripts.config.mjs scripts',
      ),
    ).toEqual(['src', 'test', 'scripts']);
  });

  it('splits a script into its invocations, each with its own config override', () => {
    // The fault injection reproduces ONE invocation, so which targets belong to
    // which config has to survive the parse.
    expect(
      eslintInvocations(
        'eslint src test *.config.* && eslint --no-config-lookup -c eslint.scripts.config.mjs scripts',
      ),
    ).toEqual([
      { configName: undefined, targets: ['src', 'test', '*.config.*'] },
      { configName: 'eslint.scripts.config.mjs', targets: ['scripts'] },
    ]);
  });

  it('does not mistake a value-taking flag argument for a target', () => {
    // `-c <file>`: the config path must not be read as something to lint.
    expect(eslintTargets('eslint -c other.config.mjs src')).toEqual(['src']);
    expect(eslintTargets('eslint --max-warnings 0 src')).toEqual(['src']);
    expect(eslintTargets('eslint --ext .ts,.tsx src')).toEqual(['src']);
  });

  it('ignores boolean flags and the --flag=value form', () => {
    expect(eslintTargets('eslint --no-error-on-unmatched-pattern --config=x.mjs src')).toEqual([
      'src',
    ]);
  });

  it('returns nothing when the script never invokes eslint', () => {
    expect(eslintTargets("echo 'no self-lint for eslint-config'")).toEqual([]);
    expect(eslintTargets('')).toEqual([]);
  });

  it('treats a directory, an ancestor, and `.` as covering the directory', () => {
    expect(targetCoversDir('src', 'src')).toBe(true);
    expect(targetCoversDir('.', 'src')).toBe(true);
    expect(targetCoversDir('./', 'src')).toBe(true);
    expect(targetCoversDir('packages', 'packages/inner')).toBe(true);
  });

  it('does NOT treat a file inside the directory as covering it', () => {
    // The false negative: lints one file, but every dir-name substring matches.
    expect(targetCoversDir('src/index.ts', 'src')).toBe(false);
    expect(targetCoversDir('middleware.ts', 'app')).toBe(false);
  });

  it('reduces a glob to its literal prefix', () => {
    expect(targetCoversDir('src/**/*.ts', 'src')).toBe(true);
    expect(targetCoversDir('**/*.ts', 'src')).toBe(true);
  });

  it('accepts the real repo forms, and rejects a narrowed one', () => {
    const covers = (script, dirs) => {
      const targets = eslintTargets(script);
      return dirs.every((d) => targets.some((t) => targetCoversDir(t, d)));
    };
    expect(covers('eslint src test eval', ['src', 'test', 'eval'])).toBe(true);
    expect(
      covers('eslint app middleware.ts test next.config.ts postcss.config.mjs vitest.config.ts', [
        'app',
        'test',
      ]),
    ).toBe(true);
    // `eslint .` is broader than the dirs it must cover — must NOT be flagged.
    expect(covers('eslint .', ['src', 'test'])).toBe(true);
    // Naming files instead of the dir must be flagged.
    expect(covers('eslint src/index.ts test/a.test.ts', ['src', 'test'])).toBe(false);
    // A dir the package ships but the script forgets must be flagged.
    expect(covers('eslint src test', ['src', 'test', 'eval'])).toBe(false);
  });

  it('treats an exact filename, `.`, and a matching glob as covering a top-level file', () => {
    expect(targetCoversFile('tsup.config.ts', 'tsup.config.ts')).toBe(true);
    expect(targetCoversFile('.', 'tsup.config.ts')).toBe(true);
    expect(targetCoversFile('./', 'tsup.config.ts')).toBe(true);
    expect(targetCoversFile('*.config.*', 'tsup.config.ts')).toBe(true);
    expect(targetCoversFile('**/*.ts', 'tsup.config.ts')).toBe(true);
    // The awkward real one: schema's drizzle config is not `<name>.config.ts`,
    // so a `*.config.{ts,mjs}` brace list would miss it and `*.config.*` must not.
    expect(targetCoversFile('*.config.*', 'drizzle.config.local.ts')).toBe(true);
    expect(targetCoversFile('*.config.{ts,mjs}', 'drizzle.config.local.ts')).toBe(false);
  });

  it('does NOT treat a source dir as covering a top-level file', () => {
    // This is the gap the bucket exists to close: `eslint src test` reaches
    // nothing in the package root, however many dirs it names.
    expect(targetCoversFile('src', 'vitest.config.ts')).toBe(false);
    expect(targetCoversFile('test', 'vitest.config.ts')).toBe(false);
    expect(targetCoversFile('src/**/*.ts', 'vitest.config.ts')).toBe(false);
  });

  it('does NOT let a non-matching glob vacuously cover a top-level file', () => {
    // targetCoversDir reduces `*.config.*` to an empty literal prefix and calls
    // it covering, which is right for a directory and wrong for a file. Matching
    // the pattern for real is what keeps `eslint app *.config.*` from claiming
    // to cover middleware.ts.
    expect(targetCoversFile('*.config.*', 'middleware.ts')).toBe(false);
    expect(targetCoversFile('*.mjs', 'vitest.config.ts')).toBe(false);
    // A glob anchored at the root does not reach into a subdirectory either.
    expect(targetCoversFile('*.config.*', 'src/a.config.ts')).toBe(false);
  });

  it('accepts the real repo forms for top-level files', () => {
    const covers = (script, files) => {
      const targets = eslintTargets(script);
      return files.every((f) => targets.some((t) => targetCoversFile(t, f)));
    };
    expect(
      covers('eslint src test *.config.*', [
        'eslint.config.mjs',
        'tsup.config.ts',
        'vitest.config.ts',
      ]),
    ).toBe(true);
    expect(
      covers('eslint app middleware.ts test *.config.*', [
        'middleware.ts',
        'next.config.ts',
        'postcss.config.mjs',
      ]),
    ).toBe(true);
    expect(covers('eslint .', ['tsup.config.ts'])).toBe(true);
    // The pre-fix form: source dirs only, root files unreachable.
    expect(covers('eslint src test', ['tsup.config.ts'])).toBe(false);
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
  /** @type {Map<string, import('eslint').Linter.Config>} */
  const configById = new Map();
  /** @type {Map<string, Error>} */
  const failureById = new Map();

  // Each resolution is caught PER TARGET. An uncaught throw here would abort
  // beforeAll, and vitest then SKIPS every test in this describe — reporting
  // zero failures, naming no package, and silently dropping the behavioral
  // verification of the whole workspace. Capturing lets the assertion below
  // report which target failed and why.
  beforeAll(async () => {
    for (const t of PROBE_TARGETS) {
      try {
        configById.set(t.id, await resolveConfig(t.pkgDir, t.relFile, t.configName));
      } catch (cause) {
        failureById.set(t.id, /** @type {Error} */ (cause));
      }
    }
  }, RESOLVE_TIMEOUT_MS);

  it('probes at least one target per guarded package', () => {
    expect(PROBE_TARGETS.length).toBeGreaterThanOrEqual(GUARDED_PACKAGES.length);
  });

  it.each(PROBE_TARGETS.map((t) => t.id))('resolves an effective config for %s', (id) => {
    expect(failureById.get(id)?.message, `${id} did not resolve`).toBeUndefined();
  });

  it.each(PROBE_TARGETS.map((t) => t.id))('bans every network form in %s', (id) => {
    const fired = firedRuleIds(NETWORK_SNIPPET, networkRulesOf(configById.get(id)));
    for (const key of KEYS) {
      expect(fired, `${id} :: ${key}`).toContain(key);
    }
  });

  // The workspace ban has two halves: the network rules above and
  // `n/no-process-env`, which CLAUDE.md pins to an exact table of opt-out sites.
  // Without this, a package could switch the rule off in its own config and add
  // an unreviewed fifth site while every other assertion here stayed green.
  // Asserted as a resolved severity rather than by adding it to KEYS, because
  // the standalone Linter has no `n` plugin registered and cannot run the rule.
  // Main configs only: networkGuard (the scripts pass) deliberately omits it.
  it.each(PROBE_TARGETS.filter((t) => t.configName === 'eslint.config.mjs').map((t) => t.id))(
    'keeps n/no-process-env at error in %s',
    (id) => {
      expect([2, 'error'], `${id} :: n/no-process-env`).toContain(
        severityOf(configById.get(id), 'n/no-process-env'),
      );
    },
  );

  it.each(PROBE_TARGETS.map((t) => t.id))('bans every listed module in %s', (id) => {
    const rules = networkRulesOf(configById.get(id));
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

describe('rootConfigFiles type-aware opt-out (real config)', () => {
  // Linting a package's top-level config files costs the type-aware rules on
  // them: no tsconfig `include` owns those paths, so the type-aware parser
  // refuses the file outright rather than reporting on it. Two things about that
  // trade have to stay true, and neither is visible from the config source —
  // flat config resolves last-wins across three or four spread blocks.
  //
  //   1. The ban the files are linted FOR is untouched. Everything syntactic
  //      survives disableTypeChecked; only the rules that need a type checker go.
  //   2. The opt-out stops at the package root. It is scoped to `*.config.*`
  //      with no `**/`, so src/ keeps the type-aware rules, which are
  //      load-bearing there.
  const cliDir = join(REPO_ROOT, 'cli');
  const resolved = { rootConfig: undefined, source: undefined };

  beforeAll(async () => {
    resolved.rootConfig = await resolveConfig(cliDir, 'tsup.config.ts');
    resolved.source = await resolveConfig(cliDir, 'src/cli.ts');
  }, RESOLVE_TIMEOUT_MS);

  it('drops the type-aware rules on a top-level config file', () => {
    // Not a goal in itself — it is the concession that makes the file lintable
    // at all. Pinned so the reason a root file parses stays visible.
    for (const rule of [
      '@typescript-eslint/no-floating-promises',
      '@typescript-eslint/no-unsafe-call',
    ]) {
      expect([0, 'off'], `${rule} on tsup.config.ts`).toContain(
        severityOf(resolved.rootConfig, rule),
      );
    }
  });

  it('keeps the network ban and every other non-type-aware rule on it', () => {
    const fired = firedRuleIds(NETWORK_SNIPPET, networkRulesOf(resolved.rootConfig));
    for (const key of KEYS) {
      expect(fired, `tsup.config.ts :: ${key}`).toContain(key);
    }
    for (const rule of [
      'n/no-process-env',
      'no-console',
      '@typescript-eslint/no-explicit-any',
      'simple-import-sort/imports',
    ]) {
      expect([2, 'error'], `${rule} on tsup.config.ts`).toContain(
        severityOf(resolved.rootConfig, rule),
      );
    }
  });

  it('does NOT leak the type-aware opt-out into src/', () => {
    for (const rule of [
      '@typescript-eslint/no-floating-promises',
      '@typescript-eslint/no-unsafe-call',
    ]) {
      expect([2, 'error'], `${rule} on src/cli.ts`).toContain(severityOf(resolved.source, rule));
    }
  });
});

// --- Fault injection: plant network code and run the real linter -------------

describe('a planted network call in a top-level file is reported', () => {
  // Everything above reasons about CONFIGURATION and never parses a file. That
  // is a real blind spot for top-level files specifically: they sit outside
  // their package's tsconfig `include`, so the type-aware parser rejects them
  // with "was not found by the project service" unless the config drops the
  // type-aware rules for that path — and a file that fails to parse reports a
  // fatal message and NO rule violations. The ban would be structurally wired,
  // behaviorally correct, and catching nothing. Only linting shows that.

  /** @type {Map<string, ESLint>} */
  const eslintByPkg = new Map();
  beforeAll(() => {
    for (const p of GUARDED_PACKAGES.filter((x) => x.hasConfig)) {
      eslintByPkg.set(p.name, new ESLint({ cwd: join(REPO_ROOT, p.dir) }));
    }
  });

  // One case per real top-level file, so a failure names the file rather than
  // the package. lintText resolves the real config for the real path and lints
  // the planted text in place of the file's own — the same fault as appending
  // it on disk, without a write that a killed run could leave behind.
  const ROOT_FILE_CASES = GUARDED_PACKAGES.filter((p) => p.hasConfig).flatMap((p) =>
    p.rootFiles.map((file) => ({ id: `${p.dir}/${file}`, pkg: p.name, dir: p.dir, file })),
  );

  it('has a case for every top-level file in every guarded package', () => {
    // A vacuous-pass guard: an empty case list would make every it.each below
    // disappear and the suite would report green while checking nothing.
    expect(ROOT_FILE_CASES.length).toBeGreaterThanOrEqual(GUARDED_PACKAGES.length);
  });

  it.each(ROOT_FILE_CASES)(
    'reports every network form planted in $id',
    async ({ pkg, dir, file }) => {
      const eslint = /** @type {ESLint} */ (eslintByPkg.get(pkg));
      const abs = join(REPO_ROOT, dir, file);
      expect(
        await eslint.isPathIgnored(abs),
        `${dir}/${file} is excluded by an eslint ignore`,
      ).toBe(false);
      const [result] = await eslint.lintText(NETWORK_SNIPPET, { filePath: abs, warnIgnored: true });
      const messages = result?.messages ?? [];
      // A fatal parse error is the failure mode this case exists for: it means
      // no rule ran, so the assertions below would be reporting on an empty set.
      expect(
        messages.filter((m) => m.fatal).map((m) => m.message),
        `${dir}/${file} did not parse, so no rule ran against it`,
      ).toEqual([]);
      const fired = new Set(messages.map((m) => m.ruleId));
      for (const key of KEYS) {
        expect(fired, `${dir}/${file} :: ${key}`).toContain(key);
      }
    },
    RESOLVE_TIMEOUT_MS,
  );
});

describe('end to end: eslint run the way the lint script runs it finds a planted root config file', () => {
  // The case above lints one path at a time, which proves the config bans the
  // network there but not that the `lint` script's own targets ENUMERATE it —
  // the half of the gap that let a `fetch()` in cli/tsup.config.ts pass
  // `pnpm lint`. So plant a real file in a package root and run eslint over the
  // targets parsed out of the real script. cli is the package to do it in: it
  // carries three top-level config files and the two-invocation script, so the
  // targets have to be split by invocation or the scripts pass lints half the
  // package under the wrong config.
  const PROBE_FILE = '__aka_network_probe__.config.ts';
  const pkg = GUARDED_PACKAGES.find((p) => p.name === '@akasecurity/cli');
  const pkgDir = pkg ? join(REPO_ROOT, pkg.dir) : '';
  const probeAbs = pkgDir ? join(pkgDir, PROBE_FILE) : '';

  // Belt and braces with the finally below: an assertion that throws mid-test
  // must never leave a file behind that turns the next `pnpm lint` red for a
  // reason nobody can trace back to here.
  afterAll(() => {
    if (probeAbs) rmSync(probeAbs, { force: true });
  });

  it('is a real package (the enumeration still finds cli)', () => {
    expect(pkg, '@akasecurity/cli is missing from the workspace enumeration').toBeDefined();
  });

  it(
    'reports the planted file with every network rule',
    async () => {
      const invocations = eslintInvocations(/** @type {{ lintScript: string }} */ (pkg).lintScript);
      const invocation = invocations.find((i) =>
        i.targets.some((t) => targetCoversFile(t, PROBE_FILE)),
      );
      expect(
        invocation,
        `no eslint invocation in cli's lint script targets a new ${PROBE_FILE} in the package root`,
      ).toBeDefined();
      const { configName, targets } = /** @type {{configName?: string, targets: string[]}} */ (
        invocation
      );

      writeFileSync(probeAbs, `${NETWORK_SNIPPET}\n`);
      try {
        const eslint = new ESLint({
          cwd: pkgDir,
          ...(configName ? { overrideConfigFile: join(pkgDir, configName) } : {}),
        });
        const results = await eslint.lintFiles(targets);
        const probe = results.find((r) => r.filePath === probeAbs);
        expect(
          probe,
          `eslint ${targets.join(' ')} never reached ${PROBE_FILE} — the lint script's targets do ` +
            'not enumerate top-level files, which is exactly how a fetch() in tsup.config.ts passed ' +
            '`pnpm lint`',
        ).toBeDefined();
        const messages = /** @type {ESLint.LintResult} */ (probe).messages;
        expect(
          messages.filter((m) => m.fatal).map((m) => m.message),
          `${PROBE_FILE} did not parse, so no rule ran against it`,
        ).toEqual([]);
        const fired = new Set(messages.map((m) => m.ruleId));
        for (const key of KEYS) {
          expect(fired, `${PROBE_FILE} :: ${key}`).toContain(key);
        }
        expect(
          /** @type {ESLint.LintResult} */ (probe).errorCount,
          'the planted file must fail the lint run, not merely warn',
        ).toBeGreaterThan(0);
      } finally {
        rmSync(probeAbs, { force: true });
      }
    },
    RESOLVE_TIMEOUT_MS,
  );
});
