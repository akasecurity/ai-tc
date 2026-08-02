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
//     directly in its root — without handing one back via an ignore flag on the
//     same invocation — and must ship an eslint.scripts.config.mjs if it
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
//  4. NON-PACKAGE: the same three questions for the git-tracked lintable files
//     that belong to NO workspace package. `turbo run lint` drives per-package
//     scripts, each with its package as the working directory, and no package's
//     `lint` script targets anything outside its own tree — a file outside every
//     package is lintable only by a pass declared in the ROOT manifest. Without
//     this leg the COUNT of such files is unobserved, so one added later is
//     unlinted by construction with every assertion above still green. BOTH
//     sides are derived, the same way everything else here is: the file set is
//     every git-tracked lintable file minus everything under a workspace package
//     directory, and the coverage set is the eslint invocations `pnpm lint`
//     really reaches — walked from the script the gates run, so an invocation
//     sitting in a script nothing executes covers nothing.
//
// The four compose into a closed loop: (1) guarantees every package ships a
// config and points eslint at everything it ships, (2) is fed the same derived
// list and proves each config enforces the ban, (3) proves the files the ban
// covers actually parse and report, (4) says the same of everything belonging to
// no package at all. A new package that forgets its config fails (1); one whose
// config fails to wire the ban fails (2); one whose root files cannot be linted
// at all fails (3); a repo-root file no pass targets fails (4).

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
//   files — every lintable tracked path, flat. Both maps above are keyed by a
//     package-relative parent, so neither can answer "which files belong to no
//     package at all"; that question needs the whole list.
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
  /** @type {string[]} */
  const files = [];
  for (const file of tracked) {
    if (!file || !LINTABLE_EXT.test(file)) continue;
    files.push(file);
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
  return { childDirs, rootFiles, files: files.sort() };
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

// The two value flags that SUBTRACT from a run instead of adding to it, so their
// values are kept per invocation rather than skipped with the rest. A target and
// an ignore of the same path cancel out: `eslint *.config.* --ignore-pattern
// vitest.config.ts` reads as covering vitest.config.ts if only the targets are
// parsed, while eslint skips the file — leaving exactly the hole a script that
// never named the file at all leaves, a fetch() there passing `pnpm lint` with
// CI green. The flat-config spelling of the same exclusion (`{ ignores: [...] }`
// in eslint.config.mjs) is caught by the isPathIgnored assertion in the
// fault-injection suite below; these live in package.json, where ESLint's own
// API never sees them.
//
// `--ignore-path` is listed for completeness rather than because it works: under
// flat config the CLI rejects the flag outright ("Invalid option
// '--ignore-path'", exit 2), so an invocation carrying one lints NOTHING. It is
// modelled as excluding everything, which is what that run really covers.
const IGNORE_VALUE_FLAGS = new Set(['--ignore-pattern', '--ignore-path']);

const unquote = (token) => token.replace(/^['"]|['"]$/g, '');

/**
 * Every eslint invocation in a `lint` script, in order — its `-c`/`--config`
 * override (undefined when the invocation uses ordinary config lookup), its
 * positional path targets, and the ignore flags that subtract from them. Kept as
 * invocations rather than one flat target list for two reasons. The
 * fault-injection run below has to reproduce ONE of them faithfully: cli lints
 * `src test *.config.*` under eslint.config.mjs and `scripts` under
 * eslint.scripts.config.mjs, so running the flattened target list under either
 * config lints half the package with the wrong ruleset. And an ignore flag binds
 * to the single eslint call it sits on, so flattening would let one invocation's
 * exclusion silently narrow another's targets.
 *
 * Only the `-c <file>` form is read for the config — the repo uses it
 * everywhere, and `--config=<file>` falls through as a plain flag, which costs
 * the config override but never a target. The ignore flags read **both**
 * spellings, because there the fallthrough costs the exclusion itself: an
 * unparsed `--ignore-pattern=<glob>` leaves the file reading as covered while
 * eslint skips it, which is the whole property this models.
 * @param {string} lintScript
 * @returns {{
 *   configName: string | undefined, targets: string[],
 *   ignorePatterns: string[], ignorePaths: string[],
 * }[]}
 */
function eslintInvocations(lintScript) {
  const invocations = [];
  for (const command of lintScript.split(/&&|\|\||;/)) {
    const tokens = command.match(/[^\s"']+|"[^"]*"|'[^']*'/g) ?? [];
    const start = tokens.findIndex((t) => /(?:^|\/)eslint$/.test(unquote(t)));
    if (start === -1) continue;
    /**
     * @type {{
     *   configName: string | undefined, targets: string[],
     *   ignorePatterns: string[], ignorePaths: string[],
     * }}
     */
    const invocation = { configName: undefined, targets: [], ignorePatterns: [], ignorePaths: [] };
    // Repeatable: every ignore flag on one invocation ADDS to its set, so
    // reading only the last would drop the earlier exclusions. A flag left with
    // no value records '', which the predicates below read as excluding
    // everything — eslint itself refuses such a command, so a script that lints
    // nothing must not parse as one that lints all of it.
    const pushIgnore = (flag, value) =>
      (flag === '--ignore-path' ? invocation.ignorePaths : invocation.ignorePatterns).push(value);
    for (let i = start + 1; i < tokens.length; i++) {
      const token = unquote(tokens[i]);
      if (token.startsWith('-')) {
        const eq = token.indexOf('=');
        const name = eq === -1 ? token : token.slice(0, eq);
        if (eq !== -1 && IGNORE_VALUE_FLAGS.has(name)) {
          // The tokenizer splits `--ignore-pattern='<glob>'` into the flag with
          // a trailing `=` plus the quoted glob, so an empty inline value takes
          // the next token.
          const inline = token.slice(eq + 1);
          pushIgnore(name, inline === '' ? unquote(tokens[++i] ?? '') : inline);
          continue;
        }
        if (ESLINT_VALUE_FLAGS.has(token)) {
          const next = tokens[i + 1];
          if (token === '-c' || token === '--config') {
            if (next !== undefined) invocation.configName = unquote(next);
          } else if (IGNORE_VALUE_FLAGS.has(token)) {
            pushIgnore(token, next === undefined ? '' : unquote(next));
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
 *
 * A flattened view for assertions only. Coverage is decided by
 * invocationsCoverDir / invocationsCoverFile, which keep each invocation's
 * ignore flags next to its own targets — flattening drops the exclusions.
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

// --- Exclusion: what an invocation's ignore flags take back out --------------
//
// Coverage and exclusion resolve their ambiguities in OPPOSITE directions, and
// the reason is the same one either way: name the file as uncovered. A target
// the matcher cannot read counts as not covering (above); an ignore it cannot
// read counts as excluding (below). Both land on a loud failure naming the file.
// The other default is the defect: a file read as covered while eslint skips it
// is unlinted by construction, and nothing else in this suite would say so.

/**
 * Whether an `--ignore-pattern` glob excludes the package-relative posix path
 * `file` from an eslint run. Mirrors targetCoversFile — the pattern is matched
 * against the filename for real rather than reduced to a literal prefix, so
 * `*.config.*` excludes vitest.config.ts and leaves middleware.ts alone, and
 * through path.posix.matchesGlob for the same reason: this package sits outside
 * the Windows CI filter, so a matcher that answered differently there would be
 * unexercised until it mattered.
 *
 * Gitignore-style negation (`!<glob>`, which RE-includes) is not modelled and
 * counts as excluding; so does a pattern the matcher rejects, and an empty one.
 * @param {string} pattern
 * @param {string} file package-relative posix path
 */
function ignoreExcludesFile(pattern, file) {
  const normalized = pattern.replace(/^\.\//, '').replace(/\/+$/, '');
  if (normalized === '' || normalized === '.' || normalized.startsWith('!')) return true;
  if (normalized === file) return true;
  if (file.startsWith(`${normalized}/`)) return true;
  try {
    return posix.matchesGlob(file, normalized);
  } catch {
    return true;
  }
}

/**
 * Whether an `--ignore-pattern` glob excludes directory `dir` from an eslint
 * run. Reduced to its literal prefix the way targetCoversDir does, because a
 * pattern whose glob opens before the directory name reaches everything under
 * it — `src/**` empties src/ while matching the string "src" not at all.
 *
 * That over-approximates on purpose: `**\/*.generated.ts` removes some files
 * from src/ rather than src/ itself, and is still reported as excluding it. The
 * opposite error ships an unlinted directory, so a narrow exclusion costs a loud
 * failure that names the package and is resolved by dropping the flag.
 * @param {string} pattern
 * @param {string} dir package-relative posix directory
 */
function ignoreExcludesDir(pattern, dir) {
  const normalized = pattern.replace(/^\.\//, '').replace(/\/+$/, '');
  if (normalized === '' || normalized === '.' || normalized.startsWith('!')) return true;
  const globAt = normalized.search(/[*?[{]/);
  const base = (globAt === -1 ? normalized : normalized.slice(0, globAt)).replace(/\/+$/, '');
  if (base === '') return true;
  return dir === base || dir.startsWith(`${base}/`);
}

/**
 * Whether one invocation's ignore flags take `path` back out of its own run.
 *
 * An `--ignore-path` excludes everything on its invocation, for two reasons that
 * agree: under flat config the ESLint CLI rejects the flag outright, so the run
 * exits 2 having linted nothing; and were it accepted, what it excludes lives in
 * the gitignore-format file it names, which this parser — reading a script
 * string, not the filesystem — never sees. So the guard names the paths and the
 * reader drops the flag, rather than the suite trusting a run it cannot account
 * for.
 *
 * `--no-ignore` is deliberately NOT modelled. It cancels every ignore on its
 * invocation, so honouring it would make this predicate report a NARROWER
 * exclusion — the one direction that can leave a file reading as covered while
 * eslint skips it. A script carrying both is reported as excluded: a false
 * positive, which fails loudly and is fixed by dropping the pair.
 * @param {{ ignorePatterns: string[], ignorePaths: string[] }} invocation
 * @param {string} path
 * @param {(pattern: string, path: string) => boolean} excludes
 */
function invocationExcludes(invocation, path, excludes) {
  if (invocation.ignorePaths.length) return true;
  return invocation.ignorePatterns.some((p) => excludes(p, path));
}

// A `lint` script covers a path when SOME invocation both targets it and does
// not ignore it. Evaluated per invocation because the two are flags on one
// eslint call: cli's scripts pass ignoring a path says nothing about whether the
// source pass still lints it.
const invocationsCoverDir = (invocations, dir) =>
  invocations.some(
    (i) =>
      i.targets.some((t) => targetCoversDir(t, dir)) &&
      !invocationExcludes(i, dir, ignoreExcludesDir),
  );

// The invocation that lints `file`, or undefined. Coverage is `!== undefined` on
// this rather than a parallel `.some(...)`, so the fault-injection cases below —
// which have to reproduce ONE invocation, with its own `-c` config — can never
// pick a different invocation than the coverage check blessed.
const coveringInvocation = (invocations, file) =>
  invocations.find(
    (i) =>
      i.targets.some((t) => targetCoversFile(t, file)) &&
      !invocationExcludes(i, file, ignoreExcludesFile),
  );

const invocationsCoverFile = (invocations, file) =>
  coveringInvocation(invocations, file) !== undefined;

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
    // A config eslint is never pointed at enforces nothing: the per-package half
    // of `pnpm lint` is `turbo run lint`, and turbo SKIPS a package with no
    // `lint` script (exit 0,
    // "No tasks were executed"). The script must also name every source dir the
    // package actually ships, or those files go unlinted by construction — and
    // must not hand one straight back with an ignore flag, which reads as
    // covered from the targets alone.
    //
    // Only the UNCONDITIONAL segments count, the same rule the repo-root walk
    // applies: a lint script is a shell string, and `eslint <a> || eslint <b>`
    // runs the second call only once the first has failed, so a green run never
    // lints <b> however the targets read.
    lintNotWired: guarded
      .filter((p) => {
        const invocations = unconditionalSegments(p.lintScript).flatMap(eslintInvocations);
        if (!invocations.some((i) => i.targets.length)) return true;
        return (p.codeDirs ?? []).some((d) => !invocationsCoverDir(invocations, d));
      })
      .map((p) => p.label),
    // Top-level files are their own bucket, and the reason is structural rather
    // than an oversight: a file sitting directly in a package root contributes
    // no directory segment, so it can never enter codeDirs and the check above
    // cannot see it however the source dirs are widened. Every package keeps its
    // build and tooling config there, which is shipped OSS source — a `fetch()`
    // in tsup.config.ts is exactly the thing the workspace ban exists to stop.
    // Each offender names its uncovered files, because neither "add a target"
    // nor "drop an ignore" is actionable without knowing which ones are missing.
    rootFilesNotWired: guarded.flatMap((p) => {
      const invocations = unconditionalSegments(p.lintScript).flatMap(eslintInvocations);
      const uncovered = (p.rootFiles ?? []).filter((f) => !invocationsCoverFile(invocations, f));
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

// --- The files that belong to no workspace package ---------------------------
//
// Everything above is per PACKAGE, and that loop has no leg for a file belonging
// to no package at all. `turbo run lint` runs each package's own `lint` script
// with that package as the working directory, and no package's script targets
// anything outside its own tree: a file outside every package is lintable only by
// a pass declared in the ROOT manifest, which runs at the repo root — and only
// when the script the gates actually invoke reaches that pass.
//
// Files INSIDE a package are the per-package leg's business even when a root
// pass is what lints them — the enforcement suites next to this file are the one
// case, covered by the root manifest's second, network-only invocation because
// @akasecurity/eslint-config's own `lint` is the deliberate no-op recorded in
// CONFIG_OPT_OUT.
//
// The set is DERIVED for the same reason codeDirs and rootFiles are: a hardcoded
// list of the files that exist today would stay green the day a new one is
// added, which is the only moment this check exists for.

/** Every workspace package directory, as a posix path. */
const PACKAGE_DIRS = WORKSPACE_PACKAGES.map((p) => p.dir.split(sep).join('/'));

/** Every git-tracked lintable file that sits under no workspace package. */
const NON_PACKAGE_FILES = LINTABLE_TRACKED.files.filter(
  (file) => !PACKAGE_DIRS.some((dir) => file.startsWith(`${dir}/`)),
);

// The exact set expected on disk, pinned (sorted) for the same reason
// EXPECTED_WORKSPACE_PACKAGE_NAMES is: the coverage check below is a filter over
// the derived list, so a derivation that silently DROPPED a file would leave it
// missing from both sides and fail nothing. An exact set fails loudly on any
// add, drop or rename — and a new package-less file is exactly the moment
// somebody should be asked which lint pass covers it.
const EXPECTED_NON_PACKAGE_FILES = [
  'commitlint.config.mjs',
  'eslint.root.config.mjs',
  'eslint.root.guard.config.mjs',
  'test/setup/no-network.ts',
  'tools/ci/egress-probe.mjs',
];

// The root script the gates run: lefthook's pre-push hook, the CI lint step and
// both release workflows all invoke `pnpm lint`. Coverage is walked FROM it, not
// collected from every script in the manifest, because an invocation nothing runs
// covers nothing: a conventional `"lint:fix": "eslint . --fix"` sitting in the
// manifest would otherwise satisfy the check below however narrow the real pass
// got, and the guard would go green while the ban stopped reaching these files.
const ROOT_LINT_ENTRY_SCRIPT = 'lint';

/**
 * The commands a script body runs UNCONDITIONALLY, and whose failure fails the
 * script. `a && b` is the only form that is both: b runs whenever a succeeded,
 * and the script exits non-zero when b does. A segment carrying any other
 * operator is dropped whole rather than read up to it, because the operator
 * defangs the command on EITHER side of itself — `||` both withholds what follows
 * (`a || b` runs b only when a FAILED) and discards what precedes it
 * (`b || true` runs b and swallows its exit code) — while `;` lets an earlier
 * failure be masked, `|` pipes, a bare `&` backgrounds, and `#` comments the rest
 * out. A form this does not model is simply not read, so whatever it would have
 * contributed goes uncredited: loud, and on the side that fails rather than the
 * side that ships unlinted.
 *
 * Both halves of the root walk go through this — the scripts a script chains AND
 * the eslint calls it makes directly. Reading the two by different rules is what
 * lets `eslint <targets> || eslint <other targets>` read as covering both while
 * the second only runs once the first has already failed, which is a file
 * reported as linted that no green run ever lints.
 * @param {string} script
 * @returns {string[]} the segments that run unconditionally
 */
const unconditionalSegments = (script) =>
  script.split('&&').filter((part) => !/\||;|&|#/.test(part));

/**
 * The other package scripts a script body runs unconditionally.
 * @param {string} script
 * @returns {string[]} the script names it runs
 */
function scriptReferences(script) {
  const names = [];
  for (const part of unconditionalSegments(script)) {
    const tokens = part.match(/[^\s"']+|"[^"]*"|'[^']*'/g) ?? [];
    const pm = tokens.findIndex((t) => /^(?:pnpm|npm|yarn)$/.test(unquote(t)));
    if (pm === -1) continue;
    // Skip the package manager's own flags, then the optional `run` verb. A flag
    // that takes a SEPARATE value (`--filter <pkg>`) leaves that value as the
    // candidate name; it will not be a script key, so nothing is followed —
    // under-approximating again rather than crediting the wrong script.
    let i = pm + 1;
    while (i < tokens.length && unquote(tokens[i]).startsWith('-')) i++;
    if (unquote(tokens[i] ?? '') === 'run') i++;
    if (i < tokens.length) names.push(unquote(tokens[i]));
  }
  return names;
}

/**
 * Every eslint invocation `pnpm <entry>` really runs, following the root scripts
 * it chains. Read out of the script BODIES rather than by the name of the pass,
 * so renaming `lint:root` cannot blind this — a rename has to update the caller,
 * which this walk reads. Deleting the chain, or making it conditional, empties
 * the list instead and every file below is reported as uncovered.
 *
 * Each unconditional segment is parsed on its own rather than handing the whole
 * body to eslintInvocations, which splits on `||` and `;` too and so credits an
 * eslint call that a green run never reaches. That parser is shared with the
 * per-package check, where a lint script is the whole command; here the command
 * is one segment of a chain and the operator between segments is the thing being
 * measured.
 * @param {Record<string, unknown> | undefined} scripts
 * @param {string} entry the script the gates invoke
 */
function rootLintInvocations(scripts, entry = ROOT_LINT_ENTRY_SCRIPT) {
  const all = scripts ?? {};
  const invocations = [];
  const seen = new Set();
  /** @param {string} name */
  const walk = (name) => {
    // A script that calls itself (or a cycle through two) must not spin.
    if (seen.has(name)) return;
    seen.add(name);
    const script = all[name];
    if (typeof script !== 'string') return;
    for (const segment of unconditionalSegments(script)) {
      invocations.push(...eslintInvocations(segment));
    }
    for (const referenced of scriptReferences(script)) walk(referenced);
  };
  walk(entry);
  return invocations;
}

const ROOT_MANIFEST = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'));
const ROOT_LINT_INVOCATIONS = rootLintInvocations(ROOT_MANIFEST.scripts);

/**
 * The files none of the given eslint invocations lints — either no target reaches
 * them, or one does and an ignore flag on that same invocation takes them back
 * out. Fed the invocations the ROOT pass really runs, so a file is reported when
 * nothing reaches it AND when the pass that would have is no longer run. Pure
 * over its inputs so the failure path is testable on synthetic input; a healthy
 * tree produces none by construction.
 * @param {string[]} files repo-relative posix paths
 * @param {ReturnType<typeof eslintInvocations>} invocations
 */
const nonPackageFilesNotWired = (files, invocations) =>
  files.filter((file) => !invocationsCoverFile(invocations, file));

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
        ? 'A config file only enforces the ban if eslint is pointed at the code. The per-package ' +
            'half of `pnpm lint` is `turbo run lint`, which SKIPS a package with no `lint` script ' +
            '(exit 0, "No tasks were executed"), and a script that lists only some directories ' +
            'leaves the rest unlinted. ' +
            'Point the `lint` script at every directory the package ships code in (a bare `.` ' +
            'counts; naming individual files does not). An `--ignore-pattern` / `--ignore-path` ' +
            'that takes a directory back out counts as not covering it, however the targets read ' +
            '— drop the flag rather than the directory. An `--ignore-path` counts as excluding ' +
            'everything its invocation was pointed at: flat-config eslint rejects the flag ' +
            'outright, so that invocation lints nothing at all. Chain two eslint calls with `&&` ' +
            'and nothing else: behind a `||` the second runs only once the first has failed, so a ' +
            `green run never lints what it targets:\n  ${lintNotWired.join('\n  ')}`
        : undefined,
    ).toEqual([]);
  });

  it('every guarded package has a lint script covering every top-level file it ships', () => {
    const { rootFilesNotWired } = configViolations(GUARDED_PACKAGES);
    expect(
      rootFilesNotWired,
      rootFilesNotWired.length
        ? 'These packages ship a lintable file directly in their root that no eslint invocation in ' +
            'their `lint` script lints — either no target reaches it, or a target does and an ' +
            '`--ignore-pattern` / `--ignore-path` on that same invocation takes it back out. ' +
            '`eslint src test` can never reach one — a root file has no ' +
            'directory segment — so it is unlinted by construction and a `fetch()` there passes ' +
            '`pnpm lint` (CLAUDE.md "No network calls"). Add a target that covers it: `*.config.*` ' +
            "covers the build and tooling config, anything else is named explicitly (see web-ui's " +
            'middleware.ts); and remove any ignore flag that excludes it again — an `--ignore-path` ' +
            'excludes everything, because flat-config eslint rejects the flag and that invocation ' +
            'lints nothing at all. A root config file also sits outside the tsconfig `include`, so the ' +
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

describe('every file outside every workspace package is linted by a repo-root pass', () => {
  it('enumerates exactly the expected package-less files (drift guard)', () => {
    // Both assertions below filter this list, so an empty or under-counted one
    // passes them while checking nothing. The exact set is also the review
    // moment: a new file here has to be pointed at a lint pass by hand.
    expect(
      [...NON_PACKAGE_FILES].sort(),
      'The set of git-tracked lintable files belonging to no workspace package changed. If a file ' +
        'was added, make sure a repo-root lint pass in the root package.json targets it (see ' +
        'CLAUDE.md "Adding a new workspace package", step 5) and list it in ' +
        'EXPECTED_NON_PACKAGE_FILES. If nothing was added, the derivation has regressed and files ' +
        'are silently missing from the coverage check below.',
    ).toEqual([...EXPECTED_NON_PACKAGE_FILES].sort());
    expect(PACKAGE_DIRS.length, 'no workspace package directories were derived').toBeGreaterThan(0);
  });

  it('turbo hashes every extension this suite counts as lintable', () => {
    // The check above only runs when turbo decides this task's hash moved, and
    // that decision is made by a glob whose extension list is written out by
    // hand. A file whose extension LINTABLE_EXT accepts but the glob omits is
    // enumerated here and hashed nowhere: turbo replays a cached green and the
    // guard never sees it. So drive the two against each other rather than
    // trusting that both lists were edited together. The candidate alphabet is
    // the ecosystem's real JS/TS extensions — an external, stable fact — not a
    // restatement of anything in this repo.
    const CANDIDATE_EXTENSIONS = ['js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx', 'mts', 'cts'];
    const lintable = CANDIDATE_EXTENSIONS.filter((ext) => LINTABLE_EXT.test(`probe.${ext}`));
    expect(lintable.length, 'LINTABLE_EXT accepts no known source extension').toBeGreaterThan(0);

    const turbo = readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8');
    const inputs = /"@akasecurity\/eslint-config#test"[\s\S]*?"inputs"\s*:\s*\[([\s\S]*?)\]/.exec(
      turbo,
    );
    expect(inputs, '@akasecurity/eslint-config#test declares no `inputs`').not.toBeNull();
    const braceGlobs = [...inputs[1].matchAll(/"([^"]*\{([^}]*)\}[^"]*)"/g)];
    expect(
      braceGlobs.length,
      'no input glob carries an extension list, so nothing here hashes source by extension',
    ).toBeGreaterThan(0);

    const missing = braceGlobs.flatMap(([, glob, list]) => {
      const hashed = new Set(list.split(',').map((e) => e.trim()));
      return lintable.filter((ext) => !hashed.has(ext)).map((ext) => `${glob} omits .${ext}`);
    });
    expect(
      missing,
      'A file with one of these extensions is enumerated by this suite but left out of the turbo ' +
        `input glob, so adding one replays a cached green:\n  ${missing.join('\n  ')}`,
    ).toEqual([]);
  });

  it('the script the gates run reaches at least one eslint invocation', () => {
    // Without this, deleting the root lint pass — or leaving it in the manifest
    // behind a `||`, where it runs only when the workspace lint already failed —
    // would empty the invocation list and the check below would report every file
    // at once: loud, but for a reason the message would not name.
    expect(
      ROOT_LINT_INVOCATIONS.length,
      `\`pnpm ${ROOT_LINT_ENTRY_SCRIPT}\` reaches no eslint invocation, so nothing the pre-push ` +
        'hook, the CI lint step or the release workflows run lints the files that belong to no ' +
        'workspace package',
    ).toBeGreaterThan(0);
  });

  it('no file outside every workspace package is left unlinted', () => {
    const uncovered = nonPackageFilesNotWired(NON_PACKAGE_FILES, ROOT_LINT_INVOCATIONS);
    expect(
      uncovered,
      uncovered.length
        ? 'These git-tracked lintable files belong to no workspace package, and no eslint ' +
            `invocation reachable from \`pnpm ${ROOT_LINT_ENTRY_SCRIPT}\` lints them — either no ` +
            'target reaches them, a target does and an ignore flag on that same invocation takes ' +
            'them back out, or the pass that would have covered them is no longer run ' +
            'unconditionally. `turbo run lint` drives per-package scripts with each package as ' +
            'the working directory, and no package script targets a file outside its own tree: ' +
            'these are unlinted by construction and a `fetch()` in one of them ships (CLAUDE.md ' +
            '"No network calls"). Add a target to the repo-root lint pass that covers them — a ' +
            'directory covers what is under it, `*.config.*` covers the repo-root build and ' +
            `tooling config, anything else is named explicitly:\n  ${uncovered.join('\n  ')}`
        : undefined,
    ).toEqual([]);
  });
});

describe('nonPackageFilesNotWired (the non-package bucket, tested on synthetic input)', () => {
  // The real tree is healthy, so the failure path above never executes against
  // it. Drive it directly to prove it fails LOUDLY and NAMES every file.
  const notWired = (script, files) => nonPackageFilesNotWired(files, eslintInvocations(script));

  it('names a file no root invocation targets', () => {
    expect(notWired('eslint test/setup tools/ci', ['commitlint.config.mjs'])).toEqual([
      'commitlint.config.mjs',
    ]);
  });

  it('names a file a target reaches and an ignore flag takes back out', () => {
    // Reads as covered from the targets alone, and eslint skips it.
    expect(
      notWired('eslint test/setup *.config.* --ignore-pattern commitlint.config.mjs', [
        'commitlint.config.mjs',
        'eslint.root.config.mjs',
      ]),
    ).toEqual(['commitlint.config.mjs']);
  });

  it('names every uncovered file rather than stopping at the first', () => {
    expect(
      notWired('eslint tools/ci', ['commitlint.config.mjs', 'test/setup/no-network.ts', 'a.mjs']),
    ).toEqual(['commitlint.config.mjs', 'test/setup/no-network.ts', 'a.mjs']);
  });

  it('reports every file when no script invokes eslint at all', () => {
    // The shape a deleted root pass leaves behind: turbo's own `lint` script
    // mentions linting and reaches nothing outside a package.
    expect(notWired('turbo run lint', ['commitlint.config.mjs'])).toEqual([
      'commitlint.config.mjs',
    ]);
  });

  it('clears files every target covers (the control)', () => {
    // Without this, a predicate that reported EVERYTHING would satisfy each
    // case above. Both target shapes the real pass uses are exercised: a
    // directory prefix, and a root-anchored glob.
    expect(
      notWired('eslint test/setup tools/ci *.config.*', [
        'commitlint.config.mjs',
        'eslint.root.config.mjs',
        'test/setup/no-network.ts',
        'tools/ci/egress-probe.mjs',
      ]),
    ).toEqual([]);
  });

  it('does not let a root-anchored glob vacuously cover a nested file', () => {
    // `*.config.*` reaches the repo root and no deeper, so a file added under a
    // new package-less directory is uncovered however the root config glob reads.
    expect(notWired('eslint *.config.*', ['test/e2e/onboarding/vitest.config.ts'])).toEqual([
      'test/e2e/onboarding/vitest.config.ts',
    ]);
  });
});

describe('rootLintInvocations (walking the root manifest from the script the gates run)', () => {
  const ROOT_PASS =
    'eslint --no-config-lookup -c eslint.root.config.mjs test/setup *.config.* && ' +
    'eslint --no-config-lookup -c eslint.root.guard.config.mjs packages/eslint-config/test';
  const targetsOf = (invocations) => invocations.map((i) => i.targets);

  it('follows the chained pass and collects both of its invocations', () => {
    expect(
      targetsOf(
        rootLintInvocations({
          lint: 'turbo run lint && pnpm lint:root',
          'lint:root': ROOT_PASS,
          test: 'turbo run test',
        }),
      ),
    ).toEqual([['test/setup', '*.config.*'], ['packages/eslint-config/test']]);
  });

  it('keeps each invocation whole, config and ignore flags included', () => {
    // The coverage predicate needs the ignore flags NEXT TO the targets they
    // subtract from, and the fault injection needs the `-c` config, so a walk
    // that flattened either would quietly weaken both.
    expect(
      rootLintInvocations({
        lint: 'pnpm lint:root',
        'lint:root': 'eslint -c eslint.root.config.mjs *.config.* --ignore-pattern commitlint.*',
      }),
    ).toEqual([
      {
        configName: 'eslint.root.config.mjs',
        targets: ['*.config.*'],
        ignorePatterns: ['commitlint.*'],
        ignorePaths: [],
      },
    ]);
  });

  it('renaming the pass carries its invocations along', () => {
    // The reason coverage is read out of the script BODIES: only the caller
    // names the pass, and the walk reads the caller.
    expect(
      targetsOf(
        rootLintInvocations({
          lint: 'turbo run lint && pnpm run lint:repo',
          'lint:repo': ROOT_PASS,
        }),
      ),
    ).toEqual([['test/setup', '*.config.*'], ['packages/eslint-config/test']]);
  });

  it('does NOT credit a script the entry never runs', () => {
    // The live hazard: a conventional `lint:fix` sitting in the manifest must not
    // make the coverage check green while the pass the gates run covers nothing.
    expect(rootLintInvocations({ lint: 'turbo run lint', 'lint:fix': 'eslint . --fix' })).toEqual(
      [],
    );
  });

  it('does NOT follow a reference the entry only conditionally runs, or cannot fail on', () => {
    // Each of these runs the pass on some other condition than "the entry
    // succeeded so far", not at all, or in a way that discards its exit code.
    // `||` is the one a careless edit produces: it reads as chained and runs the
    // root pass ONLY when the workspace lint has already failed, so every green
    // run skips it. `|| true` is the other direction — the pass runs and cannot
    // turn the script red, which is a gate that reports nothing.
    for (const lint of [
      'turbo run lint || pnpm lint:root',
      'turbo run lint ; pnpm lint:root',
      'turbo run lint | pnpm lint:root',
      'turbo run lint & pnpm lint:root',
      'turbo run lint # pnpm lint:root',
      'turbo run lint && pnpm lint:root || true',
    ]) {
      expect(rootLintInvocations({ lint, 'lint:root': ROOT_PASS }), lint).toEqual([]);
    }
  });

  it('does NOT credit an ESLINT CALL the pass only conditionally runs, or cannot fail on', () => {
    // The same rule one level in, and the one a careless edit to lint:root
    // reaches first. `eslint <a> || eslint <b>` reads as two passes and runs the
    // second only once the first has FAILED, so on every green run <b> is never
    // linted — a file the coverage check would report as covered while nothing
    // lints it, which is the whole gap this bucket exists to close. Modelled by
    // dropping the segment whole, so <a> goes uncredited too: the loud side.
    for (const lintRoot of [
      'eslint test/setup || eslint *.config.*',
      'eslint test/setup ; eslint *.config.*',
      'eslint *.config.* || true',
      'eslint test/setup | eslint *.config.*',
      'eslint test/setup & eslint *.config.*',
      'eslint test/setup # eslint *.config.*',
    ]) {
      expect(
        rootLintInvocations({ lint: 'turbo run lint && pnpm lint:root', 'lint:root': lintRoot }),
        lintRoot,
      ).toEqual([]);
    }
  });

  it('still credits the invocations AFTER a defanged segment', () => {
    // The control for the case above: dropping a segment must not drop the ones
    // that follow it, or the rule would report the real two-pass script as
    // covering nothing and the failure would name every file for the wrong
    // reason.
    expect(
      targetsOf(
        rootLintInvocations({
          lint: 'turbo run lint && pnpm lint:root',
          'lint:root': `eslint test/setup || true && ${ROOT_PASS}`,
        }),
      ),
    ).toEqual([['test/setup', '*.config.*'], ['packages/eslint-config/test']]);
  });

  it('still follows a chain whose EARLIER segment carries an operator', () => {
    // Skipping a segment must not skip the ones after it: `(a || b) && c` runs c
    // whenever the script got that far, which is the property being modelled.
    expect(
      targetsOf(
        rootLintInvocations({
          lint: 'turbo run lint || exit 1 && pnpm lint:root',
          'lint:root': ROOT_PASS,
        }),
      ).length,
    ).toBe(2);
  });

  it('collects an eslint call the entry makes directly', () => {
    expect(targetsOf(rootLintInvocations({ lint: 'eslint test/setup tools/ci' }))).toEqual([
      ['test/setup', 'tools/ci'],
    ]);
  });

  it('terminates on a self-referential or cyclic script', () => {
    expect(rootLintInvocations({ lint: 'pnpm lint' })).toEqual([]);
    expect(
      targetsOf(rootLintInvocations({ lint: 'pnpm a', a: 'pnpm b', b: 'pnpm a && eslint .' })),
    ).toEqual([['.']]);
  });

  it('tolerates a manifest with no scripts, and a missing or non-string entry', () => {
    expect(rootLintInvocations(undefined)).toEqual([]);
    expect(rootLintInvocations({})).toEqual([]);
    expect(rootLintInvocations({ test: 'turbo run test' })).toEqual([]);
    expect(rootLintInvocations({ lint: null, other: 3 })).toEqual([]);
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

  it('names a package whose lint script only conditionally invokes eslint', () => {
    // A lint script is a shell string, so the operator between two eslint calls
    // decides whether the second runs at all: `eslint <a> || eslint <b>` runs
    // <b> only once <a> has FAILED, so a green run never lints <b>. Reading the
    // targets alone would credit both and leave those dirs unlinted with the
    // guard green — the same shape the repo-root walk rejects, applied here so
    // one rule governs both. The whole segment is dropped rather than read up to
    // the operator, so the package is named for its source dirs too: loud, and
    // resolved by writing the chain with `&&`.
    for (const lintScript of [
      'eslint src || eslint test *.config.*',
      'eslint src test *.config.* || true',
      'eslint src ; eslint test *.config.*',
    ]) {
      const v = configViolations([pkg({ lintScript })]);
      expect(v.lintNotWired, lintScript).toEqual(['@akasecurity/newpkg (packages/newpkg)']);
      expect(v.rootFilesNotWired, lintScript).toEqual([
        '@akasecurity/newpkg (packages/newpkg) → vitest.config.ts',
      ]);
    }
  });

  it('clears a package whose two eslint calls are chained with &&', () => {
    // The control for the case above: the real two-pass shape three packages
    // ship must keep reading as covering everything, or the rule would report
    // the healthy tree.
    const v = configViolations([
      pkg({
        lintScript:
          'eslint src test *.config.* && eslint --no-config-lookup -c s.config.mjs scripts',
        codeDirs: ['src', 'test', 'scripts'],
        hasScriptsDir: true,
        hasScriptsConfig: true,
        scriptsExtendsShared: true,
      }),
    ]);
    expect(v.lintNotWired).toEqual([]);
    expect(v.rootFilesNotWired).toEqual([]);
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

  it('names a top-level file a target reaches and an ignore flag takes back out', () => {
    // The shape that reads as covered from the targets alone: `*.config.*` names
    // vitest.config.ts and `--ignore-pattern` removes it, so eslint skips the
    // file and a fetch() in it passes `pnpm lint` with exit 0.
    const v = configViolations([
      pkg({
        lintScript: 'eslint src test *.config.* --ignore-pattern vitest.config.ts',
        rootFiles: ['tsup.config.ts', 'vitest.config.ts'],
      }),
    ]);
    expect(v.rootFilesNotWired).toEqual([
      '@akasecurity/newpkg (packages/newpkg) → vitest.config.ts',
    ]);
    // Only the excluded file — tsup.config.ts is still covered by the same glob,
    // so an exclusion must narrow the report rather than condemn the package.
    expect(v.lintNotWired).toEqual([]);
  });

  it('names every top-level file a repeated --ignore-pattern excludes', () => {
    // The repeated flag has to survive the whole path into the report, not just
    // the parse: keeping only the first or only the last would leave one of
    // these two reading as covered. eslint.config.mjs is the control inside the
    // case — the same `*.config.*` target still reaches it, so it must not be
    // named however many ignores sit beside it.
    const v = configViolations([
      pkg({
        lintScript:
          'eslint src test *.config.* --ignore-pattern tsup.config.ts --ignore-pattern vitest.config.ts',
        rootFiles: ['eslint.config.mjs', 'tsup.config.ts', 'vitest.config.ts'],
      }),
    ]);
    expect(v.rootFilesNotWired).toEqual([
      '@akasecurity/newpkg (packages/newpkg) → tsup.config.ts, vitest.config.ts',
    ]);
  });

  it('names a top-level file excluded by an --ignore-path it cannot read', () => {
    const v = configViolations([
      pkg({ lintScript: 'eslint src test *.config.* --ignore-path .gitignore' }),
    ]);
    expect(v.rootFilesNotWired).toEqual([
      '@akasecurity/newpkg (packages/newpkg) → vitest.config.ts',
    ]);
    // An --ignore-path empties the whole invocation, so the source dirs it
    // targets go with it. Asserted here because the file bucket alone would
    // pass on a rule that reached only rootFilesNotWired.
    expect(v.lintNotWired).toEqual(['@akasecurity/newpkg (packages/newpkg)']);
  });

  it('names a package whose source dir an ignore flag excludes', () => {
    // The codeDirs half of the same gap: the target names test/, the flag takes
    // it away, and lintNotWired must see that rather than the target alone.
    const v = configViolations([pkg({ lintScript: 'eslint src test --ignore-pattern test' })]);
    expect(v.lintNotWired).toEqual(['@akasecurity/newpkg (packages/newpkg)']);
  });

  it('clears a package whose ignore flag matches nothing it ships', () => {
    // The control for both buckets above: without it, a predicate that excluded
    // everything would satisfy every ignore case here.
    const v = configViolations([
      pkg({ lintScript: 'eslint src test *.config.* --ignore-pattern dist' }),
    ]);
    expect(v.rootFilesNotWired).toEqual([]);
    expect(v.lintNotWired).toEqual([]);
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
      {
        configName: undefined,
        targets: ['src', 'test', '*.config.*'],
        ignorePatterns: [],
        ignorePaths: [],
      },
      {
        configName: 'eslint.scripts.config.mjs',
        targets: ['scripts'],
        ignorePatterns: [],
        ignorePaths: [],
      },
    ]);
  });

  it('does not mistake a value-taking flag argument for a target', () => {
    // `-c <file>`: the config path must not be read as something to lint.
    expect(eslintTargets('eslint -c other.config.mjs src')).toEqual(['src']);
    expect(eslintTargets('eslint --max-warnings 0 src')).toEqual(['src']);
    expect(eslintTargets('eslint --ext .ts,.tsx src')).toEqual(['src']);
    // The ignore flags are read rather than skipped, but their values must not
    // become targets either — a glob read as a target INFLATES coverage.
    expect(eslintTargets('eslint --ignore-pattern vitest.config.ts src')).toEqual(['src']);
    expect(eslintTargets('eslint --ignore-path .gitignore src')).toEqual(['src']);
    expect(eslintTargets("eslint --ignore-pattern='*.config.*' src")).toEqual(['src']);
  });

  it('captures the ignore flags per invocation instead of discarding them', () => {
    const [invocation] = eslintInvocations(
      'eslint src test *.config.* --ignore-pattern x.config.ts',
    );
    expect(invocation).toEqual({
      configName: undefined,
      targets: ['src', 'test', '*.config.*'],
      ignorePatterns: ['x.config.ts'],
      ignorePaths: [],
    });
  });

  it('collects a repeated --ignore-pattern rather than keeping only the last', () => {
    const [invocation] = eslintInvocations(
      'eslint . --ignore-pattern a.config.ts --ignore-pattern b.config.ts',
    );
    expect(invocation.ignorePatterns).toEqual(['a.config.ts', 'b.config.ts']);
  });

  it('reads the `=` spelling of an ignore flag, bare and quoted', () => {
    // `--config=<file>` deliberately falls through as a plain flag; an ignore
    // must not, because an unread exclusion reads as full coverage. The quoted
    // form tokenizes as `--ignore-pattern=` plus the glob, so both are pinned.
    expect(
      eslintInvocations('eslint . --ignore-pattern=vitest.config.ts')[0].ignorePatterns,
    ).toEqual(['vitest.config.ts']);
    expect(eslintInvocations("eslint . --ignore-pattern='*.config.*'")[0].ignorePatterns).toEqual([
      '*.config.*',
    ]);
    expect(eslintInvocations('eslint . --ignore-path=.gitignore')[0].ignorePaths).toEqual([
      '.gitignore',
    ]);
  });

  it('keeps the ignore flags of one invocation out of the next', () => {
    expect(
      eslintInvocations(
        'eslint src test *.config.* --ignore-pattern vitest.config.ts && ' +
          'eslint --no-config-lookup -c eslint.scripts.config.mjs scripts',
      ),
    ).toEqual([
      {
        configName: undefined,
        targets: ['src', 'test', '*.config.*'],
        ignorePatterns: ['vitest.config.ts'],
        ignorePaths: [],
      },
      {
        configName: 'eslint.scripts.config.mjs',
        targets: ['scripts'],
        ignorePatterns: [],
        ignorePaths: [],
      },
    ]);
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
    // Targets only — what an invocation NAMES, before any ignore flag subtracts
    // from it. The coverage the guard acts on is invocationsCoverDir's, below.
    const targetsCover = (script, dirs) => {
      const targets = eslintTargets(script);
      return dirs.every((d) => targets.some((t) => targetCoversDir(t, d)));
    };
    expect(targetsCover('eslint src test eval', ['src', 'test', 'eval'])).toBe(true);
    expect(
      targetsCover(
        'eslint app middleware.ts test next.config.ts postcss.config.mjs vitest.config.ts',
        ['app', 'test'],
      ),
    ).toBe(true);
    // `eslint .` is broader than the dirs it must cover — must NOT be flagged.
    expect(targetsCover('eslint .', ['src', 'test'])).toBe(true);
    // Naming files instead of the dir must be flagged.
    expect(targetsCover('eslint src/index.ts test/a.test.ts', ['src', 'test'])).toBe(false);
    // A dir the package ships but the script forgets must be flagged.
    expect(targetsCover('eslint src test', ['src', 'test', 'eval'])).toBe(false);
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
    // Targets only, as above — the ignore flags that subtract from them have
    // their own describe.
    const targetsCover = (script, files) => {
      const targets = eslintTargets(script);
      return files.every((f) => targets.some((t) => targetCoversFile(t, f)));
    };
    expect(
      targetsCover('eslint src test *.config.*', [
        'eslint.config.mjs',
        'tsup.config.ts',
        'vitest.config.ts',
      ]),
    ).toBe(true);
    expect(
      targetsCover('eslint app middleware.ts test *.config.*', [
        'middleware.ts',
        'next.config.ts',
        'postcss.config.mjs',
      ]),
    ).toBe(true);
    expect(targetsCover('eslint .', ['tsup.config.ts'])).toBe(true);
    // The pre-fix form: source dirs only, root files unreachable.
    expect(targetsCover('eslint src test', ['tsup.config.ts'])).toBe(false);
  });
});

describe('ignore flags subtract from what an invocation covers', () => {
  // An ignore flag is the one thing that makes a target read broader than the
  // run it describes. Parsing the targets alone reports `eslint *.config.*
  // --ignore-pattern vitest.config.ts` as covering vitest.config.ts, while
  // eslint skips the file — so a fetch() there passes `pnpm lint` with CI green.
  const cover = { file: invocationsCoverFile, dir: invocationsCoverDir };
  const covers = (kind, script, path) => cover[kind](eslintInvocations(script), path);

  it('excludes a top-level file the same invocation targets', () => {
    expect(covers('file', 'eslint src test *.config.*', 'vitest.config.ts')).toBe(true);
    expect(
      covers(
        'file',
        'eslint src test *.config.* --ignore-pattern vitest.config.ts',
        'vitest.config.ts',
      ),
    ).toBe(false);
  });

  it('leaves a file the ignore does not match covered', () => {
    // The other half: an exclusion must narrow the run, not blank it. Without
    // this case the predicate could return false for everything and the
    // exclusion cases above would still pass.
    expect(
      covers(
        'file',
        'eslint src test *.config.* --ignore-pattern tsup.config.ts',
        'vitest.config.ts',
      ),
    ).toBe(true);
    expect(
      covers(
        'file',
        'eslint app middleware.ts *.config.* --ignore-pattern next.config.ts',
        'middleware.ts',
      ),
    ).toBe(true);
  });

  it('honours every pattern when --ignore-pattern is repeated', () => {
    const script = 'eslint . --ignore-pattern tsup.config.ts --ignore-pattern vitest.config.ts';
    // Reading only the first or only the last would leave one of these covered.
    expect(covers('file', script, 'tsup.config.ts')).toBe(false);
    expect(covers('file', script, 'vitest.config.ts')).toBe(false);
    expect(covers('file', script, 'eslint.config.mjs')).toBe(true);
  });

  it('matches an ignore glob against the filename for real', () => {
    expect(covers('file', 'eslint . --ignore-pattern "*.config.*"', 'vitest.config.ts')).toBe(
      false,
    );
    // `*.config.*` does not reach middleware.ts, so it must stay covered — the
    // same asymmetry targetCoversFile draws, applied to the exclusion side.
    expect(covers('file', 'eslint . --ignore-pattern "*.config.*"', 'middleware.ts')).toBe(true);
  });

  it('excludes a whole source dir, so lintNotWired can see it', () => {
    expect(covers('dir', 'eslint src test', 'test')).toBe(true);
    expect(covers('dir', 'eslint src test --ignore-pattern test', 'test')).toBe(false);
    // A glob that empties the directory without naming it: `src/**` matches
    // nothing called "src", so the literal-prefix reduction is what catches it.
    expect(covers('dir', 'eslint . --ignore-pattern "src/**"', 'src')).toBe(false);
    // And a dir the pattern has nothing to do with stays covered.
    expect(covers('dir', 'eslint . --ignore-pattern "src/**"', 'test')).toBe(true);
    // The documented over-approximation, pinned rather than left in prose: a
    // pattern whose glob opens first leaves no literal prefix to compare, so it
    // reads as emptying every directory — wider than eslint really is, and the
    // failure is loud. Narrowing this to "excludes nothing" is the change that
    // would put an unlinted directory back behind a green suite.
    expect(covers('dir', 'eslint . --ignore-pattern "**/*.generated.ts"', 'src')).toBe(false);
  });

  it('treats --ignore-path as excluding everything it was pointed at', () => {
    // Two reasons agreeing: flat-config eslint rejects the flag, so the run
    // lints nothing; and what it would exclude lives in the file it names,
    // which this parser never reads. Either way the invocation covers nothing.
    expect(covers('file', 'eslint . --ignore-path .gitignore', 'vitest.config.ts')).toBe(false);
    expect(covers('dir', 'eslint src test --ignore-path .gitignore', 'src')).toBe(false);
  });

  it('is modelling flags eslint itself refuses, not ones it honours', () => {
    // The two claims the comments above lean on, pinned so they cannot rot into
    // prose that describes some other eslint. Flat config dropped ignore-path
    // altogether — hence "excludes everything", since a run carrying it lints
    // nothing — and an ignore with no value is refused outright, which is why
    // '' resolves to excluded rather than to "no exclusion".
    expect(() => new ESLint({ ignorePath: '.gitignore' })).toThrow(/ignorePath/);
    expect(() => new ESLint({ ignorePatterns: [''] })).toThrow(/ignorePatterns/);
    // The control: the spelling that DID survive still constructs, so the two
    // throws above are about these options and not about ESLint refusing every
    // option object this test hands it.
    expect(() => new ESLint({ ignorePatterns: ['vitest.config.ts'] })).not.toThrow();
  });

  it('scopes an ignore to the invocation carrying it', () => {
    // cli-shaped, and both directions matter: pooling every invocation's ignores
    // into one set would let either pass silently narrow the other. Each case
    // below is covered under per-invocation scoping and excluded under a pooled
    // one, so a flattened implementation cannot pass them.
    const ignoredInSource =
      'eslint src test *.config.* --ignore-pattern scripts && ' +
      'eslint --no-config-lookup -c eslint.scripts.config.mjs scripts';
    expect(covers('dir', ignoredInSource, 'scripts')).toBe(true);

    const ignoredInScripts =
      'eslint src test *.config.* && ' +
      'eslint --no-config-lookup -c eslint.scripts.config.mjs scripts --ignore-pattern "*.config.*"';
    expect(covers('file', ignoredInScripts, 'vitest.config.ts')).toBe(true);
    expect(covers('dir', ignoredInScripts, 'src')).toBe(true);

    // And the exclusion still binds inside the invocation that declared it.
    const ignoredForReal =
      'eslint src test *.config.* --ignore-pattern vitest.config.ts && ' +
      'eslint --no-config-lookup -c eslint.scripts.config.mjs scripts';
    expect(covers('file', ignoredForReal, 'vitest.config.ts')).toBe(false);
    expect(covers('file', ignoredForReal, 'tsup.config.ts')).toBe(true);
  });

  it('reads an ignore written in the `=` form', () => {
    // The spelling that would otherwise fall through as a plain boolean flag,
    // leaving the exclusion invisible and the file reading as covered.
    expect(covers('file', 'eslint . --ignore-pattern=vitest.config.ts', 'vitest.config.ts')).toBe(
      false,
    );
    expect(covers('file', "eslint . --ignore-pattern='*.config.*'", 'vitest.config.ts')).toBe(
      false,
    );
    expect(covers('file', 'eslint . --ignore-path=.gitignore', 'vitest.config.ts')).toBe(false);
  });

  it('resolves an ignore it cannot model to excluded, not to covered', () => {
    // Coverage and exclusion break ties in opposite directions, both landing on
    // "name the file". A `!`-negation RE-includes and is not modelled; `.` is a
    // no-op eslint excludes nothing for; an empty value comes from a trailing
    // `--ignore-pattern` with nothing after it, which eslint refuses outright.
    // All three read as excluding — wider than eslint, so the error is a loud
    // false positive rather than a file that ships unlinted. Reading any of
    // them as "no exclusion" is the defect this bucket exists to catch.
    for (const pattern of ['!vitest.config.ts', '.', '']) {
      expect(ignoreExcludesFile(pattern, 'vitest.config.ts'), pattern).toBe(true);
      expect(ignoreExcludesDir(pattern, 'src'), pattern).toBe(true);
    }
    // And that malformed script really does reach the '' case above.
    expect(covers('file', 'eslint . --ignore-pattern', 'vitest.config.ts')).toBe(false);
  });

  it('leaves a script with no ignore flag exactly as it was', () => {
    // Every real lint script in the workspace is one of these shapes, so a
    // regression here fails the whole tree rather than one package. Each is
    // paired with the dirs it must still cover — an `||` over two candidates
    // would pass on a predicate that had stopped seeing one of them.
    const REAL_SHAPES = [
      ['eslint src test *.config.*', ['src', 'test']],
      ['eslint app middleware.ts test *.config.*', ['app', 'test']],
      ['eslint src test eval *.config.*', ['src', 'test', 'eval']],
      ['eslint src *.config.*', ['src']],
      [
        'eslint src test *.config.* && eslint --no-config-lookup -c eslint.scripts.config.mjs scripts',
        ['src', 'test', 'scripts'],
      ],
    ];
    for (const [script, dirs] of REAL_SHAPES) {
      for (const dir of dirs) expect(covers('dir', script, dir), `${script} :: ${dir}`).toBe(true);
      expect(covers('file', script, 'vitest.config.ts'), script).toBe(true);
    }
    // …and the list really is the tree's. Everything else here is DERIVED from
    // the workspace on purpose; a hand-written mirror of it is only worth its
    // green while it still mirrors something, and a package rewording its lint
    // script would otherwise leave this exercising a shape nothing ships, with
    // the claim above quietly false and nothing red.
    const pinned = new Set(REAL_SHAPES.map(([script]) => script));
    const inTree = [
      ...new Set(
        GUARDED_PACKAGES.map((p) => p.lintScript).filter((s) => eslintInvocations(s).length),
      ),
    ].sort();
    expect(
      inTree.length,
      'no workspace package has a lint script that invokes eslint',
    ).toBeGreaterThan(0);
    expect(
      inTree.filter((s) => !pinned.has(s)),
      'REAL_SHAPES no longer mirrors the workspace. Add the new lint-script shape — and the dirs ' +
        'it must still cover — so this control keeps exercising what the tree actually ships.',
    ).toEqual([]);
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

describe('a planted network call in a file no workspace package owns is reported', () => {
  // The same blind spot as the case above, one level out. A repo-root file sits
  // outside tsconfig.root.json's `include` unless it is named there, so the
  // type-aware parser rejects it with "was not found by the project service"
  // unless the root config drops the type-aware rules for that path — and a file
  // that fails to parse reports a fatal message and NO rule violations. The
  // coverage check above would still be green: it reads a script string and
  // never parses anything.

  // Each file is linted through the config of the invocation that really covers
  // it, so a pass that resolved a different config than the lint script uses
  // cannot pass this by accident. `covered` is carried separately from
  // `configName`: an invocation using ordinary config lookup carries no `-c` and
  // still lints its files, so keying the failure on a missing config name would
  // report a covered file as unlinted.
  const NON_PACKAGE_CASES = NON_PACKAGE_FILES.map((file) => {
    const invocation = coveringInvocation(ROOT_LINT_INVOCATIONS, file);
    return { file, covered: invocation !== undefined, configName: invocation?.configName };
  });

  /** @type {Map<string, ESLint>} */
  const eslintByConfig = new Map();
  beforeAll(() => {
    for (const { covered, configName } of NON_PACKAGE_CASES) {
      const key = configName ?? '';
      if (!covered || eslintByConfig.has(key)) continue;
      eslintByConfig.set(
        key,
        new ESLint({
          cwd: REPO_ROOT,
          ...(configName ? { overrideConfigFile: join(REPO_ROOT, configName) } : {}),
        }),
      );
    }
  });

  it('has a case for every file outside every workspace package', () => {
    // A vacuous-pass guard: an empty case list makes every it.each below
    // disappear and the suite reports green while linting nothing. Compared
    // against the pinned set rather than against NON_PACKAGE_FILES, which this
    // list is a `.map` of — that comparison holds by construction and could
    // never go red.
    expect(NON_PACKAGE_CASES.length).toBeGreaterThanOrEqual(EXPECTED_NON_PACKAGE_FILES.length);
    expect(EXPECTED_NON_PACKAGE_FILES.length).toBeGreaterThan(0);
  });

  it.each(NON_PACKAGE_CASES)(
    'reports every network form planted in $file',
    async ({ file, covered, configName }) => {
      expect(
        covered,
        `no eslint invocation reachable from the script the gates run lints ${file}, so there is ` +
          'no lint pass to plant network code against',
      ).toBe(true);
      const eslint = /** @type {ESLint} */ (eslintByConfig.get(configName ?? ''));
      const abs = join(REPO_ROOT, ...file.split('/'));
      expect(await eslint.isPathIgnored(abs), `${file} is excluded by an eslint ignore`).toBe(
        false,
      );

      // Half one, at the EXACT path: resolve the config the covering invocation
      // produces for the real file and run the four rules against the snippet.
      // calculateConfigForFile runs the whole cascade without parsing anything,
      // so this half is sound at a path whose content it never substitutes.
      const resolved = await eslint.calculateConfigForFile(abs);
      expect(
        resolved,
        `eslint resolved no config block for ${file}, so the ban reaches it through nothing`,
      ).toBeTruthy();
      const fired = firedRuleIds(NETWORK_SNIPPET, networkRulesOf(resolved));
      for (const key of KEYS) {
        expect(fired, `${file} :: ${key}`).toContain(key);
      }

      // Half two, the parse property this case exists for: lint the file's OWN
      // bytes. A file outside every tsconfig `include` reports a fatal parse
      // error and NO rule violations — structurally wired, behaviorally correct,
      // enforcing nothing — so half one above would be describing a cascade that
      // never gets to run.
      //
      // Neither half substitutes text or plants a file, and that is the point.
      // Both alternatives make the outcome depend on timing rather than on the
      // config: `lintText(code, { filePath })` hands ESLint one text while the
      // type-aware parser's program still holds the file's own, so a rule can
      // report a fix range from the on-disk source against the substituted text
      // (`Index out of range … source text has length N`) depending on whether
      // that path is already warm; and a planted sibling is in the program only
      // if the watch picked the new file up, so it can report "not found by the
      // project service" for a directory that is plainly in the include. Both
      // were observed, at these exact paths, passing one CI job and failing
      // another on one commit.
      const [real] = await eslint.lintFiles([file]);
      expect(
        (real?.messages ?? []).filter((m) => m.fatal).map((m) => m.message),
        `${file} did not parse, so no rule could run against it whatever the cascade resolves`,
      ).toEqual([]);
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

describe('end to end: an ignore flag really does silence the run, and the guard names the file', () => {
  // The case above proves the lint script's targets ENUMERATE a root file. An
  // ignore flag is the one thing that makes that enumeration untrue: the target
  // still names the file and eslint still skips it, so the script reads as
  // covering a file that ships unlinted. That is invisible to every other check
  // here — the flags live in package.json, where ESLint's own API never sees
  // them, unlike the flat-config `{ ignores: [...] }` spelling the per-root-file
  // case catches through isPathIgnored.
  //
  // So run the real linter twice over the same real targets and the same planted
  // file, once with the flag and once without. The run WITHOUT it is the
  // positive control: without that half, "the flag silenced it" would also pass
  // on a probe eslint never reached for some unrelated reason.
  const PROBE_FILE = '__aka_ignored_probe__.config.ts';
  const pkg = GUARDED_PACKAGES.find((p) => p.name === '@akasecurity/cli');
  const pkgDir = pkg ? join(REPO_ROOT, pkg.dir) : '';
  const probeAbs = pkgDir ? join(pkgDir, PROBE_FILE) : '';

  afterAll(() => {
    if (probeAbs) rmSync(probeAbs, { force: true });
  });

  it('is a real package (the enumeration still finds cli)', () => {
    expect(pkg, '@akasecurity/cli is missing from the workspace enumeration').toBeDefined();
  });

  it(
    'lints the planted file, stops once an ignore flag is added, and is reported as uncovered',
    async () => {
      const lintScript = /** @type {{ lintScript: string }} */ (pkg).lintScript;
      const invocation = eslintInvocations(lintScript).find((i) =>
        i.targets.some((t) => targetCoversFile(t, PROBE_FILE)),
      );
      expect(
        invocation,
        `no eslint invocation in cli's lint script targets a new ${PROBE_FILE} in the package root`,
      ).toBeDefined();
      const { configName, targets } = /** @type {{configName?: string, targets: string[]}} */ (
        invocation
      );
      const overrides = configName ? { overrideConfigFile: join(pkgDir, configName) } : {};
      // Derived from the real script rather than hand-written, so the mutation
      // stays the real invocation plus one flag however that script changes —
      // the config override included, or the two would differ twice over if
      // cli ever moved its root-file target behind a second pass.
      const mutatedScript =
        `eslint ${configName ? `-c ${configName} ` : ''}${targets.join(' ')} ` +
        `--ignore-pattern ${PROBE_FILE}`;

      writeFileSync(probeAbs, `${NETWORK_SNIPPET}\n`);
      try {
        const resultFor = async (options) => {
          const results = await new ESLint({ cwd: pkgDir, ...overrides, ...options }).lintFiles(
            targets,
          );
          return results.find((r) => r.filePath === probeAbs);
        };

        // Control: the unflagged run reaches the file and fails on it.
        const linted = await resultFor({});
        expect(
          linted,
          `eslint ${targets.join(' ')} never reached ${PROBE_FILE}, so the ignored run below ` +
            'would prove nothing',
        ).toBeDefined();
        const fired = new Set(
          /** @type {ESLint.LintResult} */ (linted).messages.map((m) => m.ruleId),
        );
        for (const key of KEYS) {
          expect(fired, `${PROBE_FILE} :: ${key}`).toContain(key);
        }

        // The fault: one flag, and the same run stops failing on the same file.
        const ignored = await resultFor({ ignorePatterns: [PROBE_FILE] });
        expect(
          ignored?.errorCount ?? 0,
          `--ignore-pattern ${PROBE_FILE} did not change the run, so this case is not exercising ` +
            'the exclusion it is named for',
        ).toBe(0);

        // The guard: the same script string must now read as NOT covering it,
        // and the violation list must NAME the file rather than the package.
        expect(
          invocationsCoverFile(eslintInvocations(lintScript), PROBE_FILE),
          `the real script reads as not covering ${PROBE_FILE}, so the flagged read below would ` +
            'match it for the wrong reason',
        ).toBe(true);
        expect(
          invocationsCoverFile(eslintInvocations(mutatedScript), PROBE_FILE),
          `${mutatedScript} still reads as covering ${PROBE_FILE}, which eslint just proved it ` +
            'does not lint',
        ).toBe(false);
        const violations = configViolations([
          { .../** @type {object} */ (pkg), lintScript: mutatedScript, rootFiles: [PROBE_FILE] },
        ]);
        expect(violations.rootFilesNotWired).toEqual([
          `${/** @type {{ label: string }} */ (pkg).label} → ${PROBE_FILE}`,
        ]);
      } finally {
        rmSync(probeAbs, { force: true });
      }
    },
    RESOLVE_TIMEOUT_MS,
  );
});

describe('end to end: eslint run the way the root lint script runs it finds a planted repo-root file', () => {
  // The per-file case above proves the root config BANS the network at each of
  // those paths. It does not prove the root pass's targets ENUMERATE a file that
  // was not there when the script was written — the half of the gap that let a
  // `fetch()` in a repo-root config pass a lint run with exit 0. So plant a real
  // file at the repo root and run eslint over the targets parsed out of the real
  // root script, with that invocation's own `-c` config.
  const PROBE_FILE = '__aka_root_network_probe__.config.mjs';
  const probeAbs = join(REPO_ROOT, PROBE_FILE);

  // Belt and braces with the finally below: an assertion that throws mid-test
  // must never leave a file behind that turns the next lint run red for a reason
  // nobody can trace back to here.
  afterAll(() => {
    rmSync(probeAbs, { force: true });
  });

  it(
    'reports the planted file with every network rule',
    async () => {
      const invocation = coveringInvocation(ROOT_LINT_INVOCATIONS, PROBE_FILE);
      expect(
        invocation,
        `no eslint invocation reachable from \`pnpm ${ROOT_LINT_ENTRY_SCRIPT}\` targets a new ` +
          `${PROBE_FILE} at the repo root, so a file added there would ship unlinted`,
      ).toBeDefined();
      const { configName, targets } = /** @type {{configName?: string, targets: string[]}} */ (
        invocation
      );

      writeFileSync(probeAbs, `${NETWORK_SNIPPET}\n`);
      try {
        const eslint = new ESLint({
          cwd: REPO_ROOT,
          ...(configName ? { overrideConfigFile: join(REPO_ROOT, configName) } : {}),
        });
        const results = await eslint.lintFiles(targets);
        const probe = results.find((r) => r.filePath === probeAbs);
        expect(
          probe,
          `eslint ${targets.join(' ')} never reached ${PROBE_FILE} — the root lint pass's targets ` +
            'do not enumerate a new repo-root file, which is how a fetch() outside every ' +
            'workspace package passes a lint run',
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
