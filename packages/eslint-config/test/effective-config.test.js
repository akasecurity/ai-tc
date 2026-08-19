import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { builtinModules } from 'node:module';
import { join, matchesGlob, posix } from 'node:path';
import { pathToFileURL } from 'node:url';

import { ESLint, Linter } from 'eslint';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  cardinalFor,
  codeSpansOf,
  CONVENTIONS_DOC,
  countWordIn,
  ordinalFor,
  readConventions,
  sectionOf,
  tableOf,
} from './helpers/claude-md.js';
import {
  eslintInvocations,
  IGNORE_VALUE_FLAGS,
  lintableTrackedFiles,
  LINTABLE_EXT,
  packageLintInvocations,
  parseWorkspaceGlobs,
  REPO_ROOT,
  toPosix,
  ROOT_LINT_ENTRY_SCRIPT,
  rootLintInvocations,
  trackedEslintConfigFiles,
  trackedFiles,
  workspaceGlobs,
  workspacePackageDirs,
} from './helpers/lint-invocations.js';

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
//     a second config on top of base (web-ui: react + noDrizzleImports;
//     persistence / local-ops: base + noDrizzleImports; cli: base + the
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
//
// The reading of the `lint` scripts themselves — which invocations a green run
// makes, and which config each one runs under — lives in ./helpers, shared with
// no-network.test.js. That suite asks which CONFIGS the same scripts point ESLint
// at; a second reader would be two models of one shell string, free to disagree
// about what runs, and a file could then read as covered by one and audited by
// neither. Its unit tests stay here, next to the coverage predicates they feed.

// --- Workspace package enumeration (derived from pnpm-workspace.yaml) --------

// Packages exempt from shipping a network-guarded eslint.config.mjs, keyed by
// package name. Keep this list TINY — every entry is a hole in the no-network
// enforcement and must be a deliberate, reviewed decision, so each carries its
// reason. A package that ships lintable source belongs behind the ban, not here.
//
// It is EMPTY, and the empty state is the one worth defending. The single entry
// it used to carry was @akasecurity/eslint-config itself — the package that
// DEFINES the ban — on the reasoning that its `lint` was a deliberate no-op, so
// requiring a config eslint is never pointed at would assert nothing. True, and
// circular: a planted `fetch()` in its src/ or its vitest.config.ts passed
// `pnpm lint` with CI green. It ships a real config and a real two-pass `lint`
// script now, so every workspace package is guarded and nothing here is exempt.
const CONFIG_OPT_OUT = [];
const OPT_OUT_NAMES = new Set(CONFIG_OPT_OUT.map((o) => o.name));

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
//   subtreeFiles — dir -> every lintable tracked file anywhere beneath it, kept
//     repo-relative. childDirs answers "is there source under here" and
//     rootFiles answers "what sits directly here"; neither can enumerate the
//     files a DIRECTORY target actually hands to eslint, which is what an
//     ignore flag subtracts from. Without it a file-level ignore is invisible:
//     the directory still reads as covered, so the file is unlinted by
//     construction and no bucket names it.
const LINTABLE_TRACKED = (() => {
  const tracked = trackedFiles();
  /** @type {Map<string, Set<string>>} */
  const childDirs = new Map();
  /** @type {Map<string, Set<string>>} */
  const rootFiles = new Map();
  /** @type {Map<string, string[]>} */
  const subtreeFiles = new Map();
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
    // One index further than the loop above: that one stops at the file's
    // grandparent because it records a CHILD DIR at each step, and the file's
    // own parent has no child dir to contribute. This one records the FILE, so
    // the parent is exactly the key that must carry it.
    for (let i = 0; i < parts.length; i++) {
      const ancestor = parts.slice(0, i).join('/');
      let under = subtreeFiles.get(ancestor);
      if (!under) subtreeFiles.set(ancestor, (under = []));
      under.push(file);
    }
  }
  return { childDirs, rootFiles, subtreeFiles, files: files.sort() };
})();

/** The immediate subdirectories of `dir` that hold lintable tracked source. */
const lintableChildDirs = (dir) => [...(LINTABLE_TRACKED.childDirs.get(dir) ?? [])].sort();

/** The lintable tracked files sitting directly in `dir`, no subdirectory. */
const lintableRootFiles = (dir) => [...(LINTABLE_TRACKED.rootFiles.get(dir) ?? [])].sort();

/** Every lintable tracked file anywhere beneath `dir`, repo-relative and sorted. */
const lintableFilesUnder = (dir) => [...(LINTABLE_TRACKED.subtreeFiles.get(dir) ?? [])].sort();

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
 * Every workspace package on disk, resolved from pnpm-workspace.yaml (the
 * enumeration itself lives in ./helpers, shared with the opt-out audit, which
 * has to walk the same packages' lint scripts). `label` is what every failure
 * message prints — a package.json may legally omit `name`, and a bare
 * `undefined` in a violation list tells the reader nothing about which directory
 * to fix.
 * @returns {{
 *   name: string, dir: string, label: string, lintScript: string,
 *   hasConfig: boolean, extendsShared: boolean,
 *   codeDirs: string[], rootFiles: string[], codeFiles: string[],
 *   hasScriptsDir: boolean, hasScriptsConfig: boolean, scriptsExtendsShared: boolean,
 * }[]}
 */
function discoverWorkspacePackages() {
  return workspacePackageDirs().map((dir) => {
    const pkg = JSON.parse(readFileSync(join(REPO_ROOT, dir, 'package.json'), 'utf8'));
    const name = typeof pkg.name === 'string' && pkg.name ? pkg.name : dir;
    const configRel = join(dir, 'eslint.config.mjs');
    const configAbs = join(REPO_ROOT, configRel);
    const hasConfig = existsSync(configAbs);
    const scriptsConfigRel = join(dir, 'eslint.scripts.config.mjs');
    const scriptsConfigAbs = join(REPO_ROOT, scriptsConfigRel);
    const hasScriptsConfig = existsSync(scriptsConfigAbs);
    const codeDirs = lintableChildDirs(dir);
    return {
      name,
      dir,
      label: name === dir ? dir : `${name} (${dir})`,
      lintScript: pkg.scripts?.lint ?? '',
      hasConfig,
      extendsShared: hasConfig && extendsSharedConfig(configAbs),
      // Derived, not hardcoded: every child dir holding lintable tracked source.
      // `codeDirs` is what the lint script must cover, scripts/ included — its
      // second pass is an eslint invocation too.
      codeDirs,
      // The other half of what the lint script must cover, derived the same way.
      rootFiles: lintableRootFiles(dir),
      // The files those code dirs actually hand to eslint, package-relative. A
      // directory target is checked as a directory, so an ignore naming ONE file
      // inside it subtracts nothing the directory check can see — the dir still
      // reads as covered and the file is unlinted by construction. Enumerating
      // them is what lets that be reported by name.
      codeFiles: codeDirs.flatMap((d) =>
        lintableFilesUnder(`${dir}/${d}`).map((f) => f.slice(dir.length + 1)),
      ),
      hasScriptsDir: codeDirs.includes(SCRIPTS_DIR),
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
  '@akasecurity/ai-tc-codex',
  '@akasecurity/ai-tc-antigravity',
  '@akasecurity/audit-gate',
  '@akasecurity/cli',
  '@akasecurity/codeql-alerts-gate',
  '@akasecurity/coverage-gate',
  '@akasecurity/dashboard-ui',
  '@akasecurity/detections',
  '@akasecurity/eslint-config',
  '@akasecurity/extract',
  '@akasecurity/installer',
  '@akasecurity/local-ops',
  '@akasecurity/persistence',
  '@akasecurity/plugin-browser-extension',
  '@akasecurity/plugin-runtime',
  '@akasecurity/plugin-sdk',
  '@akasecurity/portability-gate',
  '@akasecurity/required-checks-gate',
  '@akasecurity/scanner',
  '@akasecurity/schema',
  '@akasecurity/setup-wizard',
  '@akasecurity/ui-kit',
  '@akasecurity/web-ui',
];

// The packages that MUST ship a network-guarded config (everything except the
// opt-outs). Fed to both the structural guard and the behavioral suite.
const GUARDED_PACKAGES = WORKSPACE_PACKAGES.filter((p) => !OPT_OUT_NAMES.has(p.name));

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

// --- Case: the matcher must answer the way the shell does --------------------
//
// Node's glob folds case on macOS and Windows and offers no way to turn it off.
// matchGlobPattern sets `nocase: isMacOS || isWindows` with `nocaseMagicOnly:
// true`, so a LITERAL pattern stays case-sensitive while a MAGIC one does not:
// `matchesGlob('a.Config.mjs', '*.config.*')` is true on macOS and false on
// Linux, and `globSync('*.config.*')` returns the mis-cased file there too. The
// shell that expands a lint script's targets is case-sensitive on every
// platform, so the file eslint actually receives is only ever the lower-cased
// one. Left folded, the guard credits coverage the shell will not give, and a
// root file one capital letter away from the target glob reads as linted while
// nothing lints it — with the drift guard's own message inviting the reader to
// pin it as expected.
//
// There is no option to pass, so the fold is removed by re-asking the same
// matcher in an alphabet it cannot fold: each ASCII letter maps to a distinct
// Private Use Area code point, which has no case mapping and is not a glob
// metacharacter. The map is one character to one character, so `?` arity, `/`
// separators, `**` crossing, ranges and brace lists all keep their exact
// semantics — `[a-z]` maps to a range of the same width, and an upper-case
// subject lands outside it the way it should.
//
// The raw match is kept as a conjunct so this can only ever be STRICTER than
// Node: an encoding bug costs a loud "uncovered" failure, never a silent pass.
const CASELESS_ALPHABET_BASE = 0xe000;

const encodeCase = (s) =>
  s.replace(/[A-Za-z]/g, (c) => {
    const code = c.charCodeAt(0);
    return String.fromCharCode(CASELESS_ALPHABET_BASE + (code >= 97 ? code - 97 : code - 65 + 26));
  });

/**
 * `path.posix.matchesGlob` minus the case folding Node applies on macOS and
 * Windows, so every platform answers the way the shell does.
 * @param {string} file package-relative posix path
 * @param {string} pattern
 */
const caseSensitiveMatchesGlob = (file, pattern) =>
  posix.matchesGlob(file, pattern) && posix.matchesGlob(encodeCase(file), encodeCase(pattern));

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
 * caseSensitiveMatchesGlob: posix so a Windows checkout answers identically on
 * separators, case-sensitive so macOS and Windows answer identically on case. A
 * pattern the matcher rejects counts as NOT covering: the guard then names the
 * file as uncovered, which is the side to fail on.
 * @param {string} target
 * @param {string} file package-relative posix path
 */
function targetCoversFile(target, file) {
  const normalized = target.replace(/^\.\//, '').replace(/\/+$/, '');
  if (normalized === '.' || normalized === '') return true;
  if (normalized === file) return true;
  if (file.startsWith(`${normalized}/`)) return true;
  try {
    return caseSensitiveMatchesGlob(file, normalized);
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
 * through caseSensitiveMatchesGlob for the same reason: every subject reaching
 * it is posix (git's output is posix everywhere, and globSync's native output is
 * normalized at the source above), so the posix matcher is the one that matches
 * the data's actual shape and a Windows checkout answers identically. Case is
 * pinned for the matching reason on the other axis — eslint matches an ignore
 * pattern case-sensitively on every platform, so a folded match here would
 * report a file as skipped that eslint in fact lints.
 *
 * The bare `path.matchesGlob` would alias to win32 there, and the two disagree
 * on exactly one input: a subject containing a backslash. They diverge in BOTH
 * directions — win32 reads `src\a\b.ts` as covered by `src/**\/*.ts` where posix
 * does not, and posix reads `cli\vitest.config.ts` as covered by `*.config.*`
 * where win32 does not — so a native path leaking past the normalization would
 * not merely be matched loosely, it would flip answers by pattern shape with the
 * host. Pinning the matcher keeps that one bug (a missed normalization) from
 * turning into two different verdicts.
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
    return caseSensitiveMatchesGlob(file, normalized);
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
  // Three buckets below read the same package's invocations, and a lint script is
  // a shell string that has to be tokenized to answer any of them. Parse once.
  const parsed = new Map();
  const invocationsFor = (p) => {
    let invocations = parsed.get(p);
    if (!invocations) parsed.set(p, (invocations = packageLintInvocations(p.lintScript)));
    return invocations;
  };
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
        const invocations = invocationsFor(p);
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
      const invocations = invocationsFor(p);
      const uncovered = (p.rootFiles ?? []).filter((f) => !invocationsCoverFile(invocations, f));
      return uncovered.length ? [`${p.label} → ${uncovered.join(', ')}`] : [];
    }),
    // The third bucket, and the one neither of the two above can reach. A code
    // dir is checked AS A DIRECTORY, and an ignore pattern is reduced to its
    // literal prefix to answer that — so `--ignore-pattern test/probe.test.ts`
    // reduces to a base that neither equals `test` nor prefixes it, the
    // directory goes on reading as covered, and eslint skips the file. That is
    // worse than an unguarded path rather than equal to it: the reviewer who
    // checks coverage finds a green guard, and a fetch() in that file ships.
    //
    // Only dirs that READ AS COVERED are walked. Where the directory itself is
    // uncovered, lintNotWired already names the package, and listing every file
    // beneath it would bury that one line under hundreds. So the two buckets
    // partition the failure rather than both reporting it.
    filesNotWired: guarded.flatMap((p) => {
      const invocations = invocationsFor(p);
      const covered = new Set(
        (p.codeDirs ?? []).filter((d) => invocationsCoverDir(invocations, d)),
      );
      const uncovered = (p.codeFiles ?? []).filter(
        (f) => covered.has(f.split('/')[0]) && !invocationsCoverFile(invocations, f),
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

// --- The files that belong to no workspace package ---------------------------
//
// Everything above is per PACKAGE, and that loop has no leg for a file belonging
// to no package at all. `turbo run lint` runs each package's own `lint` script
// with that package as the working directory, and no package's script targets
// anything outside its own tree: a file outside every package is lintable only by
// a pass declared in the ROOT manifest, which runs at the repo root — and only
// when the script the gates actually invoke reaches that pass.
//
// Files INSIDE a package are the per-package leg's business, including the
// enforcement suites next to this file: they used to be the one exception,
// covered by a second invocation in the ROOT manifest because
// @akasecurity/eslint-config's own `lint` was a deliberate no-op. That package
// lints itself now, so its `test/` is covered by the derived per-package check
// like any other code dir, and there is no exception left.
//
// The set is DERIVED for the same reason codeDirs and rootFiles are: a hardcoded
// list of the files that exist today would stay green the day a new one is
// added, which is the only moment this check exists for.

/** Every workspace package directory, as a posix path. */
const PACKAGE_DIRS = WORKSPACE_PACKAGES.map((p) => p.dir);

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
  'test/fixtures/adversarial/hostile-repo/index.ts',
  'test/helpers/remove-tree.ts',
  'test/setup/no-network.ts',
  'test/vitest/coverage.ts',
  'tools/ci/egress-probe.mjs',
];

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
/**
 * The file a directory is probed through: a synthetic NAME carrying a real
 * EXTENSION, and both halves are load-bearing in opposite directions.
 *
 * The extension is taken from a file the directory really ships, because a
 * config only claims the extensions it is written for — a `.ts` probe aimed at
 * this package's own `test/`, which is plain JS behind `eslint.guard.config.mjs`,
 * matches no block at all and reports "no config" while every real file there is
 * governed perfectly well. Hardcoding `.ts` (with `.mjs` for `scripts/`) is the
 * same inference-from-a-name this derivation exists to remove, one level down.
 *
 * The NAME stays synthetic because a real path can resolve a file-scoped
 * OVERRIDE rather than the directory's general rules — `plugin-sdk/src`'s first
 * tracked file is one of CLAUDE.md §3's documented `n/no-process-env` opt-out
 * sites, so probing it would report the package as failing a ban it holds
 * everywhere the exception does not reach. The probes want the block a new file
 * would land in, which is exactly what a name nothing overrides resolves.
 * @param {{ codeFiles: string[] }} p @param {string} dir
 */
const probeFileFor = (p, dir) => {
  const real = p.codeFiles.find((f) => f.startsWith(`${dir}/`));
  if (real === undefined) return undefined;
  // `lastIndexOf` on a dotless name returns -1, and `slice(-1)` would hand back
  // its final CHARACTER as the extension — a probe name resolving no block,
  // reported as a config failure rather than as the derivation fault it is.
  const dot = real.lastIndexOf('.');
  return dot === -1 ? undefined : `${dir}/__network_ban_probe__${real.slice(dot)}`;
};

/**
 * The package-relative config an invocation runs under, or undefined when it
 * resolves none. A `-c` names it outright; without one, ordinary flat-config
 * lookup from the package root finds `eslint.config.mjs` — unless
 * `--no-config-lookup` cancelled that lookup, which leaves the invocation
 * running under no config at all.
 * @param {{ configName?: string, noConfigLookup: boolean }} invocation
 */
const invocationConfigName = (invocation) =>
  invocation.configName ?? (invocation.noConfigLookup ? undefined : 'eslint.config.mjs');

// Each probe path is paired with the config the invocation that REALLY lints it
// runs under, never with one inferred from the path's own name. The inference
// this replaced modelled two shapes — everything under `eslint.config.mjs`, plus
// a hardcoded `scripts/` case — and a package linting a directory any other way
// was silently paired with a config that `--no-config-lookup` guarantees never
// applies there. This package is that case: its `test/` runs under
// `eslint.guard.config.mjs`, so the whole enforcement suite sat behind a config
// no probe exercised, and switching the ban off there left every test green.
//
// Pairing by invocation removes the shape mapping and the `scripts/` special
// case together, so a THIRD shape added later is probed by construction rather
// than by someone remembering to extend a table.
/**
 * Every (path, config) probe pair one package contributes. Pure over its input,
 * so the paths that must FAIL are drivable with a synthetic package the way
 * configViolations' are — a real, healthy tree produces no unresolved pair by
 * construction, which would otherwise leave that branch untested.
 * @param {Pick<ReturnType<typeof discoverWorkspacePackages>[number],
 *   'dir' | 'hasConfig' | 'lintScript' | 'codeDirs' | 'codeFiles' | 'rootFiles'
 *   | 'hasScriptsConfig'>} p
 */
function probeTargetsFor(p) {
  if (!p.hasConfig) return [];
  const pkgDir = join(REPO_ROOT, p.dir);
  const invocations = packageLintInvocations(p.lintScript);

  /**
   * One (path, config) pair. A path no invocation lints, and a path whose
   * invocation resolves no config, both yield a target carrying `unresolved`
   * rather than no target at all — a shape that generated nothing would be
   * skipped silently, which is the failure mode this whole derivation exists to
   * remove.
   * @param {string} relFile @param {string} label
   */
  const probe = (relFile, label) => {
    if (relFile === undefined) {
      return {
        id: `${toPosix(p.dir)}/<no file> @ ${label}`,
        pkgDir,
        configName: undefined,
        relFile: label,
        unresolved:
          `${label} enumerated no tracked file to probe through, so the ban protecting ` +
          'it is exercised by nothing',
      };
    }
    const invocation = coveringInvocation(invocations, relFile);
    const configName = invocation ? invocationConfigName(invocation) : undefined;
    return {
      // POSIX, never `join`: an id is compared as text (below, and in the
      // per-config assertions), and `join` yields backslashes on Windows — where
      // this package's suite really runs — so a native id fails a check that
      // holds everywhere else.
      id: `${toPosix(p.dir)}/${configName ?? '<no config>'} @ ${label}`,
      pkgDir,
      configName,
      relFile,
      unresolved: !invocation
        ? `no eslint invocation in this package's \`lint\` script lints ${label}, so the ban ` +
          'protecting it is exercised by nothing'
        : configName === undefined
          ? `the invocation linting ${label} passes --no-config-lookup with no -c, so it runs ` +
            'under no config at all'
          : undefined,
    };
  };

  // Top-level files are probed at their REAL paths, never a synthetic name.
  // Which config block claims a root file depends on its filename — the build
  // and tooling config resolves through `rootConfigFiles` with the type-aware
  // rules off, while web-ui's middleware.ts keeps them — so an invented name
  // would exercise a block that no real file resolves to.
  // A `scripts/` dir whose files are all build output contributes no codeDir,
  // but its `eslint.scripts.config.mjs` still governs whatever lands there — so
  // the config is included on its own account and reports as unresolved rather
  // than vanishing. Dropping it because nothing is tracked yet is how a config
  // ends up asserted by nothing.
  const probeDirs = [...new Set([...p.codeDirs, ...(p.hasScriptsConfig ? [SCRIPTS_DIR] : [])])];
  return [
    ...probeDirs.map((d) => probe(probeFileFor(p, d), `${d}/`)),
    ...p.rootFiles.map((f) => probe(f, f)),
  ];
}

const PROBE_TARGETS = GUARDED_PACKAGES.flatMap(probeTargetsFor);

/** Probe targets by id, so an `it.each` case does not rescan the whole list. */
const PROBE_TARGET_BY_ID = new Map(PROBE_TARGETS.map((t) => [t.id, t]));

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
            `...base / ...noDrizzleImports / ...react):\n  ${notExtending.join('\n  ')}`
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

  it('every guarded package lints every file inside the dirs it covers', () => {
    // The bucket is a FILTER over the derived file list, so a derivation that
    // resolved nothing would leave it empty and this assertion green for the one
    // reason it must never be green for. Prove the enumeration reached the tree
    // before trusting the silence, the same rule the parse checks above apply.
    const enumerated = GUARDED_PACKAGES.flatMap((p) => p.codeFiles);
    expect(
      enumerated.length,
      'no guarded package enumerated a single file inside its code dirs — the subtree index has ' +
        'regressed and this check is passing vacuously',
    ).toBeGreaterThan(0);
    // Every code dir a package ships must contribute, or a dir could drop out of
    // the enumeration and take its files with it while the total stayed healthy.
    for (const p of GUARDED_PACKAGES) {
      for (const dir of p.codeDirs) {
        expect(
          p.codeFiles.some((f) => f.startsWith(`${dir}/`)),
          `${p.label} ships ${dir}/ but enumerated no file under it`,
        ).toBe(true);
      }
    }

    const { filesNotWired } = configViolations(GUARDED_PACKAGES);
    expect(
      filesNotWired,
      filesNotWired.length
        ? 'These packages ship a tracked source file that their `lint` script targets by ' +
            'DIRECTORY and then takes back out with an `--ignore-pattern` / `--ignore-path` on the ' +
            'same invocation. The directory still reads as covered, so nothing else here reports ' +
            'it — and eslint skips the file, so a fetch() in it passes `pnpm lint` with CI green ' +
            '(CLAUDE.md "No network calls"). Drop the ignore flag rather than the directory: an ' +
            'ignore that names one file is exactly the shape this bucket exists to catch, and an ' +
            '`--ignore-path` excludes its whole invocation because flat-config eslint rejects the ' +
            `flag outright:\n  ${filesNotWired.join('\n  ')}`
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

// A package that imports a `node:` builtin, or reads `import.meta.dirname`,
// needs `@types/node` in its OWN manifest — and omitting it typechecks fine from
// inside this workspace, because TypeScript walks up to the repo root's
// node_modules/@types and finds the copy the root devDependencies installed.
// So the defect is invisible here by construction and surfaces only where the
// package is consumed from a workspace that does not install this root: TS2307
// on the `node:` specifier, TS2339 on `import.meta.dirname`.
//
// It is also invisible in the lockfile in a way worth naming, because that is
// the second thing declaring the dependency fixes. Undeclared, pnpm resolved
// vitest's optional `@types/node` peer for those importers independently of what
// TypeScript resolved from the root — landing a major above the `engines` floor
// while the compiler used the root's copy. Two versions in play for one package.
//
// Three packages carried this at once, which is what makes it a pattern rather
// than an oversight and the reason it is derived here instead of remembered.
describe('every workspace package declares the @types/node its own source needs', () => {
  // The two symptoms above, plus the BARE form of the first. `process.` still
  // looks like it belongs and does not: `child_process.` contains it, so the
  // token needs a boundary it cannot carry, and a package whose only Node
  // surface is a global is not a case this repo has.
  //
  // A bare `from 'fs'` needs the types exactly as `node:fs` does, and nothing
  // here forces the prefix: no `n/prefer-node-protocol` is configured, and the
  // network-module ban reaches the bare form for those modules alone. No package
  // carries one today — which is the reason the alternation is DERIVED rather
  // than written out. A hand-listed set is what goes stale before the first case
  // arrives, and `builtinModules` is an external, stable fact about the runtime,
  // the same shape as CANDIDATE_EXTENSIONS below. The closing quote is what
  // keeps `fs` off `fs-extra`; `path/posix` matches under its own alternative
  // rather than through `path`.
  const BARE_BUILTINS = builtinModules
    .filter((m) => !m.startsWith('node:'))
    .sort((a, b) => b.length - a.length);
  const NEEDS_NODE_TYPES = new RegExp(
    `\\b(?:from|import|require)\\s*\\(?\\s*['"](?:node:|(?:${BARE_BUILTINS.join('|')})['"])` +
      `|import\\.meta\\.(?:dirname|filename)\\b`,
  );

  /** Every lintable tracked file the package itself owns, nested packages excluded. */
  const ownFiles = (pkg) => {
    const dir = `${pkg.dir}/`;
    return LINTABLE_TRACKED.files.filter(
      (f) =>
        f.startsWith(dir) &&
        !PACKAGE_DIRS.some((other) => other !== dir.slice(0, -1) && f.startsWith(`${other}/`)),
    );
  };

  const usage = WORKSPACE_PACKAGES.map((pkg) => {
    const manifest = JSON.parse(readFileSync(join(REPO_ROOT, pkg.dir, 'package.json'), 'utf8'));
    const files = ownFiles(pkg).filter((f) =>
      NEEDS_NODE_TYPES.test(stripComments(readFileSync(join(REPO_ROOT, f), 'utf8'))),
    );
    return {
      label: pkg.label,
      files,
      declared:
        manifest.devDependencies?.['@types/node'] ?? manifest.dependencies?.['@types/node'] ?? '',
    };
  });

  it('finds the node-typed source it is filtering for (vacuity guard)', () => {
    // Every assertion below filters `usage`, so a regex that matched nothing —
    // or an ownFiles() that resolved no path on a platform whose separator is
    // not '/' — would report zero violations and pass having checked nothing.
    const withUsage = usage.filter((u) => u.files.length);
    expect(
      withUsage.map((u) => u.label),
      'no package reads as using a node: builtin, so the checks below are vacuous',
    ).not.toEqual([]);
    expect(withUsage.length).toBeGreaterThan(WORKSPACE_PACKAGES.length / 2);
  });

  it('reads a bare builtin specifier as needing the types, and a look-alike as not', () => {
    // No package imports a bare builtin today, so every assertion below that
    // filters `usage` would pass unchanged with the bare alternation deleted.
    // This is the only thing holding that half, which is why it drives the
    // pattern directly rather than through the tracked tree.
    const matches = (src) => NEEDS_NODE_TYPES.test(src);
    for (const src of [
      "import { readFileSync } from 'node:fs';",
      "import { readFileSync } from 'fs';",
      "const { join } = require('path');",
      "import 'os';",
      "import { win32 } from 'path/win32';",
      'import.meta.dirname',
    ]) {
      expect(matches(src), `should read as needing @types/node: ${src}`).toBe(true);
    }
    // The closing quote earning its place: each of these contains a builtin
    // name and needs nothing.
    for (const src of [
      "import x from 'fs-extra';",
      "import x from 'node-fetch';",
      "import x from './fs';",
      "import x from 'vitest';",
    ]) {
      expect(matches(src), `should NOT read as needing @types/node: ${src}`).toBe(false);
    }
    // The alternation is derived, so a runtime that stopped reporting builtins
    // would silently empty it while every case above still passed on `node:`.
    expect(BARE_BUILTINS, 'builtinModules reported no bare builtin').toContain('fs');
  });

  it('no package uses a node: builtin without declaring @types/node', () => {
    const undeclared = usage
      .filter((u) => u.files.length && !u.declared)
      .map((u) => `${u.label} — e.g. ${u.files.slice(0, 3).join(', ')}`);
    expect(
      undeclared,
      undeclared.length
        ? 'These packages import a node: builtin (or read import.meta.dirname) but declare no ' +
            '@types/node of their own. They typecheck here only because TypeScript falls back to ' +
            "the repo root's node_modules/@types, and fail with TS2307/TS2339 from any workspace " +
            `that does not install this root. Add "@types/node" to devDependencies:\n  ${undeclared.join('\n  ')}`
        : undefined,
    ).toEqual([]);
  });

  it('every declared @types/node tracks the one Active LTS line', () => {
    // Split ranges are the state this replaced, one layer down: the point of
    // declaring the dependency is that ONE version is in play per package.
    //
    // The ROOT manifest is in the set because it is a real consumer of this
    // range and not a workspace package: tsconfig.root.json sets
    // `"types": ["node"]` and `typecheck:root` runs over test/setup, test/vitest,
    // tools/ci and eslint.root.config.mjs against whatever copy the root
    // declares. Derived from WORKSPACE_PACKAGES alone, a root-only bump puts two
    // majors in play — the exact state this block exists to prevent — and stays
    // green, because the drift is outside every set the check reads.
    const rootDeclared =
      ROOT_MANIFEST.devDependencies?.['@types/node'] ??
      ROOT_MANIFEST.dependencies?.['@types/node'] ??
      '';
    // Non-vacuity: `filter(Boolean)` below drops an undeclared root silently,
    // so the root would leave the comparison rather than fail it.
    expect(
      rootDeclared,
      `The root package.json declares no @types/node, but tsconfig.root.json sets ` +
        `"types": ["node"] and typecheck:root runs against it.`,
    ).not.toBe('');

    const declarers = [
      ...usage.map((u) => ({ label: u.label, declared: u.declared })),
      { label: 'the repo root (package.json)', declared: rootDeclared },
    ].filter((d) => d.declared);
    const ranges = [...new Set(declarers.map((d) => d.declared))];
    expect(
      ranges,
      `More than one @types/node range is declared: ` +
        `${declarers.map((d) => `${d.label} ${d.declared}`).join(', ')}. ` +
        `${CONVENTIONS_DOC} states .nvmrc, CI and @types/node all track the Active LTS line.`,
    ).toHaveLength(1);
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

  it('turbo hashes every tracked file this suite actually reads', () => {
    // The extension check above asks whether the globs SPELL the right file
    // types. This asks whether they REACH the files — a different question, and
    // the one the repo-root entry exists for: `$TURBO_ROOT$/*/**/*.{…}` requires
    // a directory segment, so a file at the root matches no per-package glob
    // however its extension is spelled. Same hazard at the other end of the
    // tree, where a `!` exclusion can take back a path the positive globs cover.
    //
    // inline-disables.test.js reads every one of these files, so a path outside
    // the hash is a file someone can add a disable to while turbo replays a
    // cached green and the inventory never runs.
    const turbo = readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8');
    const inputs = /"@akasecurity\/eslint-config#test"[\s\S]*?"inputs"\s*:\s*\[([\s\S]*?)\]/.exec(
      turbo,
    );
    expect(inputs, '@akasecurity/eslint-config#test declares no `inputs`').not.toBeNull();
    const declared = [...inputs[1].matchAll(/"([^"]*)"/g)].map((m) => m[1]);
    const rooted = (prefix) =>
      declared.filter((g) => g.startsWith(prefix)).map((g) => g.slice(prefix.length));
    const included = rooted('$TURBO_ROOT$/');
    const excluded = rooted('!$TURBO_ROOT$/');

    const files = lintableTrackedFiles();
    expect(files.length, 'no tracked lintable files, so this asserts nothing').toBeGreaterThan(0);
    expect(included.length, 'no repo-rooted input globs to match against').toBeGreaterThan(0);

    // `path.matchesGlob` folds case on macOS and Windows. That can only make
    // this MORE permissive, and every glob here is structural (`*`, `**`, an
    // extension list) rather than a spelled path, so no verdict below turns on
    // it — but a future entry naming a real path should not rely on the case.
    const unhashed = files.filter(
      (file) =>
        !included.some((glob) => matchesGlob(file, glob)) ||
        excluded.some((glob) => matchesGlob(file, glob)),
    );
    expect(
      unhashed,
      "These tracked files are read by this package's suites but hashed by none of the task's " +
        `turbo inputs, so editing one alone replays a cached green:\n  ${unhashed.join('\n  ')}`,
    ).toEqual([]);
  });

  it('turbo hashes the conventions doc this suite reads', () => {
    // Same hazard as the extension check above, one file type over. Two describes
    // in this package parse CLAUDE.md and assert its opt-out tables against the
    // tree; none of the input globs reaches a .md, so without an entry of its own
    // the document could be edited — or gutted — with this task's hash untouched,
    // turbo replaying the cached pass and the guards never running on the change.
    // A broader glob would do, but it has to be spelled here either way.
    const turbo = readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8');
    const inputs = /"@akasecurity\/eslint-config#test"[\s\S]*?"inputs"\s*:\s*\[([\s\S]*?)\]/.exec(
      turbo,
    );
    expect(inputs, '@akasecurity/eslint-config#test declares no `inputs`').not.toBeNull();
    const globs = [...inputs[1].matchAll(/"([^"]*)"/g)].map((m) => m[1]);
    expect(
      globs,
      `${CONVENTIONS_DOC} is parsed by this suite but hashed by none of its turbo inputs, so ` +
        'editing it alone replays a cached green',
    ).toContain(`$TURBO_ROOT$/${CONVENTIONS_DOC}`);
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

describe(`the root pass states the ignore-flag rule (${CONVENTIONS_DOC} step 5)`, () => {
  // The ignore rule is enforced for the ROOT pass by nonPackageFilesNotWired, and
  // stated for a PACKAGE by the paragraph earlier in step 5. Prose sitting beside
  // an enforced property inherits none of its guard, so a reader who takes the
  // package paragraph as the general rule has nothing telling them it also binds
  // `lint:root` — and a reader who does not is one flag away from a repo-root file
  // that reads as covered and is never linted.
  //
  // Anchored on the boundary between the two halves rather than on the claim
  // itself. An anchor that IS the claim disappears with it, and a slice that
  // cannot find its anchor reports a missing anchor rather than a missing rule —
  // the deletion this guard exists to catch would read as a broken guard.
  const ROOT_HALF_ANCHOR = 'Files **outside every package**';
  const STEP_5_SECTION = '## Adding a new workspace package';

  /** Step 5's text from the repo-root half onward. Throws rather than returning ''. */
  function rootHalf() {
    const section = sectionOf(readConventions(), STEP_5_SECTION);
    const at = section.indexOf(ROOT_HALF_ANCHOR);
    if (at === -1) {
      throw new Error(
        `${CONVENTIONS_DOC} ${STEP_5_SECTION}: no ${JSON.stringify(ROOT_HALF_ANCHOR)} — the guard ` +
          'cannot tell where the repo-root half begins, so it would assert against the package ' +
          'paragraph and pass on prose that says nothing about `lint:root`.',
      );
    }
    if (section.indexOf(ROOT_HALF_ANCHOR, at + 1) !== -1) {
      throw new Error(
        `${CONVENTIONS_DOC}: ${JSON.stringify(ROOT_HALF_ANCHOR)} occurs more than once, so this ` +
          'slice starts at whichever came first rather than at the root half.',
      );
    }
    return section.slice(at);
  }

  // A flag named in prose, normalized: `--ignore-pattern=<glob>` is the same flag
  // as `--ignore-pattern`, and comparing the spellings rather than the flags would
  // fail on a rewording that changed nothing.
  const ignoreFlagsNamedIn = (text) =>
    [
      ...new Set(
        codeSpansOf(text)
          .map((span) => span.split('=')[0].trim())
          .filter((span) => span.startsWith('--ignore')),
      ),
    ].sort();

  it('names every ignore flag the coverage check models, and no other', () => {
    // Both directions. A doc that drops one leaves contributors told about half
    // the rule; a doc that names one the parser does not model promises an
    // enforcement that is not there. Compared against the modelled set rather
    // than a literal pair, so adding a third flag to IGNORE_VALUE_FLAGS fails
    // here until the prose catches up.
    expect(
      ignoreFlagsNamedIn(rootHalf()),
      `${CONVENTIONS_DOC} step 5's repo-root half must state the ignore-flag rule for ` +
        '`lint:root`, naming each flag the coverage check subtracts by. The package paragraph ' +
        'above it states the same rule; a reader has no way to know it also binds the root pass ' +
        'unless this half says so.',
    ).toEqual([...IGNORE_VALUE_FLAGS].sort());
  });

  it('states a rule the root walk really applies (each flag, with the control)', () => {
    // The prose assertion above is only worth its green while the behaviour it
    // describes is real. Drive the ROOT walk — not the per-package one — with each
    // flag the doc names, through the same rootLintInvocations the live check uses.
    const FILE = 'commitlint.config.mjs';
    const targets = 'eslint -c eslint.root.config.mjs *.config.*';
    const walk = (lintRoot) =>
      nonPackageFilesNotWired(
        [FILE],
        rootLintInvocations({ lint: 'pnpm lint:root', 'lint:root': lintRoot }),
      );

    // The control, in the same case: without a flag the root pass reaches the
    // file. Without this half, a predicate that reported EVERYTHING would satisfy
    // every expectation below and the rule would look enforced while nothing was.
    expect(
      walk(targets),
      `${targets} does not reach ${FILE}, so the flagged runs prove nothing`,
    ).toEqual([]);

    for (const flag of IGNORE_VALUE_FLAGS) {
      expect(
        walk(`${targets} ${flag} ${FILE}`),
        `${flag} does not take ${FILE} back out of the root pass, so ${CONVENTIONS_DOC}'s claim ` +
          'that it counts as uncovered is false',
      ).toEqual([FILE]);
    }
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
  // A SYNTHETIC two-invocation pass. The real `lint:root` is a single invocation
  // today — its second one moved into @akasecurity/eslint-config's own `lint`
  // when that package stopped opting out — but the walker still has to collect
  // every invocation of a chained script, which is what every per-package
  // two-pass `lint` script depends on. Keeping the fixture chained is what pins
  // that; the walker never opens either config, so the names need only be
  // distinct.
  const ROOT_PASS =
    'eslint --no-config-lookup -c eslint.root.config.mjs test/setup *.config.* && ' +
    'eslint --no-config-lookup -c eslint.second.config.mjs tools/ci';
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
    ).toEqual([['test/setup', '*.config.*'], ['tools/ci']]);
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
        noConfigLookup: false,
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
    ).toEqual([['test/setup', '*.config.*'], ['tools/ci']]);
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
    ).toEqual([['test/setup', '*.config.*'], ['tools/ci']]);
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

  it('every entry is a real workspace package with a reason', () => {
    // A loop rather than it.each, because the list is EMPTY and it.each over an
    // empty array registers no test at all. Vacuous today by construction — the
    // pin below is what keeps it that way, and this is what meets the first
    // entry anybody adds.
    for (const { name, reason } of CONFIG_OPT_OUT) {
      expect(names, `${name} is not a workspace package`).toContain(name);
      // The reason is the whole point of the list — an entry without one is an
      // undocumented hole in the no-network enforcement.
      expect(reason?.trim(), `${name} has no reason`).toBeTruthy();
    }
  });

  it('is empty — every workspace package is guarded', () => {
    // Hard-coded so ANY addition to the opt-out is a reviewed change here rather
    // than a silent hole in the no-network enforcement (mirrors the ban-set
    // drift guards in no-network.test.js). The list held exactly one entry until
    // @akasecurity/eslint-config started linting itself; going back to a
    // non-empty list means arguing a package out of the ban in review.
    expect(CONFIG_OPT_OUT.map((o) => o.name)).toEqual([]);
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
    rootFiles: ['vitest.config.ts'],
    codeFiles: ['src/index.ts', 'test/ordinary.test.ts', 'test/probe.test.ts'],
    hasScriptsDir: false,
    hasScriptsConfig: false,
    scriptsExtendsShared: false,
    ...over,
  });

  it('names a file an ignore takes out of a directory that still reads as covered', () => {
    // The shape the directory check structurally cannot see. `test` is targeted
    // and the ignore names one file inside it, so the literal-prefix reduction
    // the dir check uses reports no exclusion — the package reads as fully
    // covered while eslint skips that file. Nothing above this bucket reports
    // it, which is what makes the exposure worse than an unguarded path: the
    // reviewer who checks coverage finds a green guard.
    const v = configViolations([
      pkg({ lintScript: 'eslint src test *.config.* --ignore-pattern test/probe.test.ts' }),
    ]);
    expect(v.filesNotWired).toEqual(['@akasecurity/newpkg (packages/newpkg) → test/probe.test.ts']);
    // …and the two older buckets stay silent, which is the whole point: without
    // the new one the package passes every coverage check in this suite.
    expect(v.lintNotWired).toEqual([]);
    expect(v.rootFilesNotWired).toEqual([]);
  });

  it('leaves a package with no ignore flag alone', () => {
    // The control. Without it the bucket could name every file in the workspace
    // and every case above would still pass.
    expect(configViolations([pkg({})]).filesNotWired).toEqual([]);
    expect(
      configViolations([pkg({ lintScript: 'eslint . ' })]).filesNotWired,
      'a bare `.` covers every file beneath it',
    ).toEqual([]);
  });

  it('leaves an ignore that misses every shipped file alone', () => {
    // Narrowing must be real. An ignore naming a file the package does not ship
    // subtracts nothing, so reporting here would be over-reporting — and would
    // send someone to drop a flag that costs no coverage.
    expect(
      configViolations([
        pkg({ lintScript: 'eslint src test *.config.* --ignore-pattern test/absent.test.ts' }),
      ]).filesNotWired,
    ).toEqual([]);
  });

  it('leaves a whole-directory exclusion to the directory bucket', () => {
    // The two buckets partition the failure rather than both reporting it.
    // `--ignore-pattern test` empties the directory, so lintNotWired names the
    // package and this bucket stays quiet — otherwise one mistake prints one
    // line plus every file beneath it, burying the actionable line.
    const v = configViolations([
      pkg({ lintScript: 'eslint src test *.config.* --ignore-pattern test' }),
    ]);
    expect(v.lintNotWired).toEqual(['@akasecurity/newpkg (packages/newpkg)']);
    expect(v.filesNotWired).toEqual([]);
  });

  it('names every ignored file, not just the first', () => {
    // A `.find`-shaped reduction would report one and leave the rest unlinted
    // with the guard green after a single fix.
    const v = configViolations([
      pkg({
        lintScript:
          'eslint src test *.config.* --ignore-pattern test/probe.test.ts --ignore-pattern src/index.ts',
      }),
    ]);
    expect(v.filesNotWired).toEqual([
      '@akasecurity/newpkg (packages/newpkg) → src/index.ts, test/probe.test.ts',
    ]);
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

  it('reads a package script by ONE rule, so coverage and fault injection cannot disagree', () => {
    // configViolations blesses a package through packageLintInvocations, and the
    // fault-injection describes below reproduce ONE of those invocations to plant
    // a file against. Both must read the script the same way: if the injection
    // parsed the raw string it could pick an invocation out of a segment a green
    // run never executes, and then lint a probe through a pass that does not run.
    // The two halves below are the control — the rules genuinely differ on this
    // script, which is what makes routing the call sites load-bearing rather than
    // cosmetic.
    const script = 'eslint src || eslint *.config.*';
    expect(
      invocationsCoverFile(packageLintInvocations(script), 'vitest.config.ts'),
      'the conditional segment must be dropped, so nothing can be injected through it',
    ).toBe(false);
    expect(
      invocationsCoverFile(eslintInvocations(script), 'vitest.config.ts'),
      'raw parsing must still credit it — otherwise this case proves nothing about which rule is used',
    ).toBe(true);
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
      filesNotWired: [],
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
        noConfigLookup: false,
        targets: ['src', 'test', '*.config.*'],
        ignorePatterns: [],
        ignorePaths: [],
      },
      {
        configName: 'eslint.scripts.config.mjs',
        noConfigLookup: true,
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
      noConfigLookup: false,
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
    // An unread exclusion reads as full coverage, so both spellings are parsed.
    // The quoted form tokenizes as `--ignore-pattern=` plus the glob, so both
    // are pinned.
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
        noConfigLookup: false,
        targets: ['src', 'test', '*.config.*'],
        ignorePatterns: ['vitest.config.ts'],
        ignorePaths: [],
      },
      {
        configName: 'eslint.scripts.config.mjs',
        noConfigLookup: true,
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

  it('reads every spelling of the config flag, and records --no-config-lookup', () => {
    // `-c <file>` is what the repo writes today; the other two are what a
    // contributor or a generated script may write tomorrow. Which config an
    // invocation runs under is read here and acted on by the §4 opt-out audit,
    // so an unread spelling is a real ruleset the audit never inspects — not a
    // cosmetic gap. `--no-config-lookup` is the third state: with it and no
    // `-c`, the run uses NO config file rather than the one lookup would find.
    for (const flag of ['-c x.config.js', '--config x.config.js', '--config=x.config.js']) {
      expect(eslintInvocations(`eslint ${flag} src`)[0].configName, flag).toBe('x.config.js');
      expect(eslintTargets(`eslint ${flag} src`), flag).toEqual(['src']);
    }
    expect(eslintInvocations("eslint --config='x.config.js' src")[0].configName).toBe(
      'x.config.js',
    );
    expect(eslintInvocations('eslint src')[0].noConfigLookup).toBe(false);
    expect(eslintInvocations('eslint --no-config-lookup src')[0].noConfigLookup).toBe(true);
    // A repeated config flag: eslint keeps the last, so this does too.
    expect(eslintInvocations('eslint -c a.mjs --config b.mjs src')[0].configName).toBe('b.mjs');
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

  it('matches case-sensitively, the way the shell that expands the target does', () => {
    // A lint script's targets are expanded by the SHELL, which is case-sensitive
    // on every platform, so `eslint *.config.*` only ever hands eslint the
    // lower-cased file. A folded match credits coverage nothing gives: the file
    // reads as linted and no pass lints it.
    expect(targetCoversFile('*.config.*', 'a.Config.mjs')).toBe(false);
    expect(targetCoversFile('*.config.*', 'A.CONFIG.MJS')).toBe(false);
    expect(targetCoversFile('*.CONFIG.*', 'a.config.mjs')).toBe(false);
    expect(targetCoversFile('**/*.TS', 'src/a.ts')).toBe(false);
    // Positive control on the same patterns — without these the case above is
    // satisfied by a predicate that stopped matching anything at all.
    expect(targetCoversFile('*.config.*', 'a.config.mjs')).toBe(true);
    expect(targetCoversFile('**/*.ts', 'src/a.ts')).toBe(true);
    // A range maps to a range of the same width, so it narrows by case too.
    expect(targetCoversFile('[a-z]*.ts', 'abc.ts')).toBe(true);
    expect(targetCoversFile('[a-z]*.ts', 'Abc.ts')).toBe(false);
    expect(targetCoversFile('[A-Z]*.ts', 'Abc.ts')).toBe(true);
    expect(targetCoversFile('[A-Z]*.ts', 'abc.ts')).toBe(false);
  });

  it('does not inherit the raw matcher, which folds case on some hosts', () => {
    // The positive control for the case above: on macOS and Windows the raw
    // matcher answers the OPPOSITE, which is the defect targetCoversFile used to
    // carry. Pinning the disagreement rather than a fixed value keeps this
    // meaningful on both kinds of host, and turns a future Node that stops
    // folding into a red test rather than a silently redundant workaround.
    const rawFolds = posix.matchesGlob('a.Config.mjs', '*.config.*');
    expect(rawFolds).toBe(process.platform === 'darwin' || process.platform === 'win32');
    expect(targetCoversFile('*.config.*', 'a.Config.mjs')).toBe(false);
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

  it('matches an ignore glob case-sensitively, as eslint does', () => {
    // eslint matches an ignore pattern case-sensitively on every platform. A
    // folded match here reports a file as skipped that eslint in fact lints —
    // the guard would name a covered file as uncovered and send someone to
    // widen a pass that was already reaching it.
    expect(covers('file', 'eslint . --ignore-pattern "*.config.*"', 'a.Config.mjs')).toBe(true);
    // Positive control: the same ignore on the correctly-cased file still bites.
    expect(covers('file', 'eslint . --ignore-pattern "*.config.*"', 'a.config.mjs')).toBe(false);
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
    // paired with the dirs its TARGETS reach — an `||` over two candidates
    // would pass on a predicate that had stopped seeing one of them.
    //
    // What is pinned here is the DIRECTORY reading, and that is deliberately
    // narrower than "these dirs are fully linted". An ignore naming one file
    // leaves its directory reading as covered, so pinning coverage here would
    // record that as intended and hide it. Whether every file is really linted
    // is derived from the tree by `every guarded package lints every file
    // inside the dirs it covers`, never asserted from this list.
    const REAL_SHAPES = [
      ['eslint src test *.config.*', ['src', 'test']],
      // The benchmark harness adds a third code directory to the packages that
      // carry benchmarks. `bench/` imports product code and test helpers, so it
      // is source like any other and has to sit behind the same bans.
      ['eslint src test bench *.config.*', ['src', 'test', 'bench']],
      ['eslint app middleware.ts test *.config.*', ['app', 'test']],
      ['eslint src test eval *.config.*', ['src', 'test', 'eval']],
      ['eslint src *.config.*', ['src']],
      // tools/installer ships no `src` at all: the thing under test is the
      // two shell scripts at the package root, which ESLint does not lint,
      // and `test/` is the whole of its JavaScript.
      ['eslint test *.config.*', ['test']],
      [
        'eslint src test *.config.* && eslint --no-config-lookup -c eslint.scripts.config.mjs scripts',
        ['src', 'test', 'scripts'],
      ],
      // The same shape once a package grows a `bench/`. A benchmark imports
      // product code and builds fixtures like any other source here, so it sits
      // behind the same bans rather than outside every lint pass.
      [
        'eslint src test bench *.config.* && eslint --no-config-lookup -c eslint.scripts.config.mjs scripts',
        ['src', 'test', 'bench', 'scripts'],
      ],
      // The same two-pass split, with `test` rather than `scripts` behind the
      // network-only config: @akasecurity/eslint-config's own suites are plain JS
      // full of untyped fixtures and banned-primitive strings, so the full
      // ruleset covers src/ and the root configs while the second pass covers
      // test/.
      [
        'eslint src *.config.* && eslint --no-config-lookup -c eslint.guard.config.mjs test',
        ['src', 'test'],
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
      'REAL_SHAPES no longer mirrors the workspace. Add the new lint-script shape here — and the ' +
        'dirs its TARGETS reach — so this control keeps exercising what the tree actually ships. ' +
        'Pin what the targets reach, NOT what you expect to end up linted: an ignore flag can ' +
        'leave a directory reading as covered while eslint skips a file inside it, and asserting ' +
        'coverage here would record that as intended. Whether every file is really linted is ' +
        'decided by `every guarded package lints every file inside the dirs it covers`, which ' +
        'derives the answer from the tree rather than from this list.',
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
      // A pair the derivation could not build has no config to resolve, so it
      // skips resolution — but it is still a TARGET, so it still appears in
      // every `it.each` below and `probeProblem` reports its reason. Emitting no
      // target is the failure mode that matters: a lint-pass shape nobody
      // modelled would then generate no case at all, and a suite that runs no
      // assertion reports green.
      if (t.unresolved) continue;
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

  it('pairs each directory with the config the invocation linting it really runs', () => {
    // The derivation's whole point, stated as an outcome rather than a restatement
    // of the code. Every package running a SECOND eslint pass under its own `-c`
    // must show up here paired with THAT config — under the shape mapping this
    // replaced they were all paired with `eslint.config.mjs`, and a directory
    // behind a differently-shaped pass was asserted by nothing.
    const byConfig = (name) =>
      PROBE_TARGETS.filter((t) => t.configName === name)
        .map((t) => t.id)
        .sort();

    // Derived, not hardcoded: every package whose lint script names a `-c` config
    // must own a probe under it, so a fifth second-pass package is covered the day
    // it lands rather than when someone remembers this list.
    const secondPassPairs = GUARDED_PACKAGES.flatMap((p) =>
      packageLintInvocations(p.lintScript)
        .map(invocationConfigName)
        .filter((name) => name !== undefined && name !== 'eslint.config.mjs')
        .map((name) => `${toPosix(p.dir)}/${name}`),
    ).sort();
    expect(
      secondPassPairs.length,
      'no package runs a second eslint pass under its own -c, so this control exercises nothing',
    ).toBeGreaterThan(0);
    for (const configRel of secondPassPairs) {
      expect(
        PROBE_TARGETS.filter((t) => t.configName).map(
          (t) => `${toPosix(t.pkgDir.slice(REPO_ROOT.length + 1))}/${t.configName}`,
        ),
        `${configRel} governs a directory that no probe pairs it with`,
      ).toContain(configRel);
    }

    // The case that motivated this: this package's own suites run under
    // eslint.guard.config.mjs, never the sibling eslint.config.mjs that
    // --no-config-lookup guarantees does not apply there.
    expect(byConfig('eslint.guard.config.mjs')).toEqual([
      'packages/eslint-config/eslint.guard.config.mjs @ test/',
    ]);
    expect(
      byConfig('eslint.config.mjs'),
      'packages/eslint-config/test/ must not be paired with the config that never lints it',
    ).not.toContain('packages/eslint-config/eslint.config.mjs @ test/');
  });

  it('reports a directory it could build no config pair for, rather than skipping it', () => {
    // Driven directly: a lint pass nobody modelled must FAIL, not vanish. A derivation that emitted nothing for an unknown shape would leave
    // `it.each` with no case, and a suite that runs no assertion reports green.
    const orphan = {
      dir: 'packages/newpkg',
      codeDirs: ['src'],
      codeFiles: ['src/index.ts'],
      rootFiles: [],
      hasConfig: true,
      lintScript: "echo 'no eslint here'",
    };
    const built = probeTargetsFor(orphan);
    expect(built.map((t) => t.id)).toHaveLength(1);
    expect(built[0].unresolved).toMatch(/no eslint invocation/);
    // …and the control: the same package with a real pass resolves cleanly, so
    // the case above is not simply "this helper always reports unresolved".
    const healthy = probeTargetsFor({ ...orphan, lintScript: 'eslint src' });
    expect(healthy[0].unresolved).toBeUndefined();
    expect(healthy[0].configName).toBe('eslint.config.mjs');
  });

  it('reports a scripts config whose directory ships no tracked file', () => {
    // A `scripts/` dir that is entirely build output contributes no codeDir, so
    // the derivation has no file to take a probe extension from — but the config
    // still governs whatever lands there. It must be named, not dropped: a
    // config asserted by nothing is the failure this whole pass exists to catch.
    const built = probeTargetsFor({
      dir: 'packages/newpkg',
      codeDirs: ['src'],
      codeFiles: ['src/index.ts'],
      rootFiles: [],
      hasConfig: true,
      hasScriptsConfig: true,
      lintScript: 'eslint src && eslint --no-config-lookup -c eslint.scripts.config.mjs scripts',
    });
    const scripts = built.find((t) => t.id.endsWith('@ scripts/'));
    expect(scripts, 'no probe was built for the scripts config at all').toBeDefined();
    expect(scripts.unresolved).toMatch(/enumerated no tracked file/);
    // The control: src/ ships a file, so it resolves rather than reporting too.
    expect(built.find((t) => t.id.endsWith('@ src/')).unresolved).toBeUndefined();
  });

  /**
   * Why a probe target cannot be exercised, or undefined. Reads the target's OWN
   * `unresolved` reason as well as any resolution throw, so a pair the derivation
   * could not build is reported whatever the loop above chose to record. Routing
   * this through `failureById` alone would let the whole unresolved branch be
   * deleted with every case still green — the real tree builds no unresolved pair,
   * so nothing would execute the deletion.
   * @param {{ unresolved?: string }} target @param {Error | undefined} failure
   */
  const probeProblem = (target, failure) => target.unresolved ?? failure?.message;

  it.each(PROBE_TARGETS.map((t) => t.id))('resolves an effective config for %s', (id) => {
    const target = /** @type {(typeof PROBE_TARGETS)[number]} */ (PROBE_TARGET_BY_ID.get(id));
    expect(probeProblem(target, failureById.get(id)), `${id} did not resolve`).toBeUndefined();
  });

  it('reports an unresolved target through the same predicate the cases read', () => {
    // Drives probeProblem on both sides, because the real tree produces no
    // unresolved target and so exercises only the healthy one. Without this the
    // predicate could ignore `unresolved` entirely and every case above would
    // still pass.
    expect(probeProblem({ unresolved: 'no invocation lints src/' }, undefined)).toBe(
      'no invocation lints src/',
    );
    expect(probeProblem({}, new Error('resolution threw'))).toBe('resolution threw');
    expect(probeProblem({}, undefined)).toBeUndefined();
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

// ---------------------------------------------------------------------------
// The process.env opt-out table
// ---------------------------------------------------------------------------

// The check above holds the rule at `error` everywhere, which is the half a
// severity assertion can see. §3's table makes three further claims it cannot:
// WHICH files opt out, HOW each one does it, and that there are no others. All
// three sat in prose no test read — the section could be deleted outright and
// this package stayed green — and the table already carries a wrong `Why` for
// one row, which is what an unread claim looks like after a while.
//
// So each column is driven against the thing it describes: the site against the
// tree, the mechanism against the resolved config and the file's own text, and
// the count against the row count. The `Why` column is prose about intent and
// stays unguarded; nothing here should be read as covering it.
const SECTION_3 = '### 3. `process.env` is off by default';
const ENV_TABLE_HEADER = ['Site', 'Mechanism', 'Why'];
/** "Four places in shipped source genuinely need the host environment…" */
const ENV_COUNT_SENTENCE = /(\w+) places in shipped source genuinely need the host environment/g;
/** "Adding a fifth site means updating this table." */
const ENV_ADDING_SENTENCE = /Adding (?:an? )?(\w+)(?: opt-out)? site means updating this table/g;
/** The two mechanisms the table distinguishes, spelled as it spells them. */
const BY_CONFIG = 'file-scoped ESLint config';
const BY_INLINE = 'inline `eslint-disable-next-line`';
/** An actual disable DIRECTIVE for the rule — not a mention of it in prose. */
const INLINE_DISABLE = /eslint-disable(?:-next-line|-line)?\b[^\n]*\bn\/no-process-env\b/;

/**
 * What §3's phrase "in shipped source" has to EXCLUDE for its sentence to be
 * true. Widen this without widening the sentence and the table silently stops
 * describing the tree; widen the sentence without this and the count stops
 * matching. They move together, and the sentence names the same three kinds.
 *
 * Test harnesses: several spawn the real hooks as child processes and need the
 * host PATH, so they carry inline disables of their own.
 *
 * `tools/`: repo tooling, never shipped — the Repository layout section says so
 * in those words. A CI gate there reads the runner's own output channels
 * (GITHUB_STEP_SUMMARY), which is not "the host environment" in the sense this
 * table is about, and tabling it would put a file that ships to nobody in a
 * table of shipped opt-outs.
 *
 * Neither exclusion loses the inventory: inline-disables.test.js reads the whole
 * tracked tree and pins the set EXACTLY, so a disable dropping out of this
 * table's scope lands in that one rather than in nothing.
 */
const isTestPath = (file) => file.split('/').some((seg) => seg === 'test' || seg === '__tests__');
const isRepoTooling = (file) => file.startsWith('tools/');
const isShippedSource = (file) => !isTestPath(file) && !isRepoTooling(file);

/** Resolved configs report severity numerically; a config entry spells it. */
const isOff = (severity) => severity === 0 || severity === 'off';

/**
 * The nearest ancestor of `file` that ships an `eslint.config.mjs` — the package
 * whose config governs it, and the cwd its `lint` script runs in. Derived by
 * walking up rather than by matching a `packages/`/`plugins/` prefix, which
 * would silently pick the wrong directory for a repo-root package like `cli`.
 */
function owningConfigDir(file) {
  for (let parts = file.split('/').slice(0, -1); parts.length; parts = parts.slice(0, -1)) {
    const dir = parts.join('/');
    if (existsSync(join(REPO_ROOT, dir, 'eslint.config.mjs'))) return dir;
  }
  throw new Error(`No ancestor of ${file} ships an eslint.config.mjs, so no config governs it.`);
}

describe(`the process.env opt-out table (${CONVENTIONS_DOC} §3)`, () => {
  let section = '';
  /** @type {{site: string, mechanism: string}[]} */
  let rows = [];
  /** @type {Error | undefined} */
  let setupError;
  /** Each tabled site's resolved `n/no-process-env` severity. */
  const severityBySite = new Map();
  /** Config entries that switch the rule off, as `<config>: <files pattern>`. */
  const configOptOuts = [];

  // Caught end to end, per the note on the hook above: an uncaught throw here
  // SKIPS every test below instead of failing one, so a resolution that started
  // erroring would read as a guard with nothing to say.
  beforeAll(async () => {
    try {
      section = sectionOf(readConventions(), SECTION_3);
      rows = tableOf(section, ENV_TABLE_HEADER).map(([site, mechanism], i) => {
        const spans = codeSpansOf(site);
        if (spans.length !== 1) {
          throw new Error(`Row ${i + 1}: the Site cell must name exactly one file, got ${site}.`);
        }
        return { site: spans[0], mechanism };
      });

      for (const { site } of rows) {
        const dir = owningConfigDir(site);
        const config = await resolveConfig(join(REPO_ROOT, dir), site.slice(dir.length + 1));
        severityBySite.set(site, severityOf(config, 'n/no-process-env'));
      }

      // Only configs that NAME the rule can be switching it off, so the module
      // load is confined to those — one file today, rather than all eighteen.
      // Enumerated through the shared reader, whose basename test accepts any
      // extension ESLint honours: a `*.mjs` glob here would miss an opt-out in
      // an `eslint.extra.config.js`, which ESLint applies exactly the same.
      const candidates = trackedEslintConfigFiles().filter((f) =>
        readFileSync(join(REPO_ROOT, f), 'utf8').includes('no-process-env'),
      );
      for (const file of candidates) {
        const mod = await import(pathToFileURL(join(REPO_ROOT, file)).href);
        for (const entry of mod.default) {
          if (!isOff(severityOf(entry, 'n/no-process-env'))) continue;
          // §3 prefers a file-scoped opt-out precisely because a package-wide one
          // is invisible to a reader auditing the configs. Recorded as a finding
          // rather than skipped, so it cannot vanish from the count below.
          for (const pattern of entry.files ?? ['<package-wide>']) {
            configOptOuts.push(`${file}: ${pattern}`);
          }
        }
      }
    } catch (cause) {
      setupError = /** @type {Error} */ (cause);
    }
  }, RESOLVE_TIMEOUT_MS);

  const parsed = () => {
    if (setupError) throw setupError;
    return rows;
  };

  it('reads a non-empty opt-out table out of the document', () => {
    expect(parsed().length).toBeGreaterThan(0);
  });

  it('names a tracked file that really reads the host environment in every row', () => {
    const tracked = new Set(LINTABLE_TRACKED.files);
    const wrong = parsed().flatMap(({ site }) => {
      if (!tracked.has(site)) return [`${site}: tabled site is not a tracked lintable file`];
      return readFileSync(join(REPO_ROOT, site), 'utf8').includes('process.env')
        ? []
        : [`${site}: tabled as an opt-out but reads no process.env`];
    });
    expect(wrong, `${CONVENTIONS_DOC} §3 rows that do not describe the tree`).toEqual([]);
  });

  it('describes each site with the mechanism that really exempts it', () => {
    // The two mechanisms are distinguishable from the outside: a config opt-out
    // resolves the rule to `off` for that path, an inline one leaves it at error
    // and puts a disable directive in the file. Swap a row's mechanism and one of
    // the two halves fails, whichever direction the swap went.
    const wrong = parsed().flatMap(({ site, mechanism }) => {
      const severity = severityBySite.get(site);
      const inline = INLINE_DISABLE.test(readFileSync(join(REPO_ROOT, site), 'utf8'));
      if (mechanism === BY_CONFIG) {
        return isOff(severity)
          ? []
          : [
              `${site}: tabled as a config opt-out, but its config resolves the rule to ${severity}`,
            ];
      }
      if (mechanism === BY_INLINE) {
        return [
          ...(inline
            ? []
            : [`${site}: tabled as an inline disable, but carries no such directive`]),
          ...(isOff(severity)
            ? [`${site}: tabled as an inline disable, but its config already exempts the file`]
            : []),
        ];
      }
      return [`${site}: unrecognised mechanism ${JSON.stringify(mechanism)}`];
    });
    expect(wrong, `${CONVENTIONS_DOC} §3's Mechanism column vs the real configs`).toEqual([]);
  });

  it('tables every opt-out shipped source actually carries', () => {
    // The promise the section makes to the next author. Without this the count
    // sentence is only arithmetic on the rows already there: a fifth site could
    // land, be enforced, and never appear — which is the state the sentence
    // exists to prevent.
    const tabled = new Set(parsed().map((r) => r.site));
    const undocumented = LINTABLE_TRACKED.files
      .filter(
        (f) => isShippedSource(f) && INLINE_DISABLE.test(readFileSync(join(REPO_ROOT, f), 'utf8')),
      )
      .filter((f) => !tabled.has(f))
      .map((f) => `${f}: disables n/no-process-env inline and is in no §3 row`);
    expect(
      undocumented,
      `These files opt out of n/no-process-env and ${CONVENTIONS_DOC} §3 does not table them`,
    ).toEqual([]);

    // The config half, counted by `files:` pattern rather than by entry: adding a
    // path to an existing block is the way a second site hides behind the first.
    expect(
      configOptOuts.length,
      `config-level opt-outs found: ${JSON.stringify(configOptOuts)}`,
    ).toBe(parsed().filter((r) => r.mechanism === BY_CONFIG).length);
    expect(configOptOuts.filter((o) => o.endsWith('<package-wide>'))).toEqual([]);
  });

  it('states a count that follows from the table rather than from memory', () => {
    const n = parsed().length;
    expect(countWordIn(section, ENV_COUNT_SENTENCE, 'how many places opt out')).toBe(
      cardinalFor(n),
    );
    expect(['another', ordinalFor(n + 1)]).toContain(
      countWordIn(section, ENV_ADDING_SENTENCE, 'what the next author must update'),
    );
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

describe('the ban reaches the source that defines it', () => {
  // This package's src/ is the ban's own implementation, and it is also the only
  // source dir in the workspace that ESLint RUNS rather than merely reads: every
  // package's eslint.config.mjs imports @akasecurity/eslint-config, so resolving a
  // config anywhere executes src/index.js first — and src/react.js too, for the
  // packages that take the /react entry.
  //
  // Nothing above points at those files. The composition suite probes src/ at a
  // SYNTHETIC path (`src/__network_ban_probe__.ts`), which proves the cascade bans
  // the network for a hypothetical file there while naming no real one, and the
  // top-level case covers only files sitting directly in the package root, which
  // these are not. So the ban's own source was reasoned about by both and read by
  // neither.
  //
  // This must NEVER become an on-disk plant, and that is the whole reason it is
  // written as two halves that leave the file byte-for-byte alone. Appending a
  // module-scope `fetch()` to src/index.js produces no lint error at all: ESLint
  // imports the file to build the config, so the call RUNS, and the process dies
  // with `TypeError: fetch failed` before a rule has been applied to anything. The
  // run exits non-zero, which is what makes it dangerous — a check asserting only
  // "the lint run failed" passes on that crash, and would go on passing with every
  // network rule deleted. Half one resolves the cascade at the real path without
  // parsing; half two parses the real bytes without substituting any.
  const PKG_DIR = 'packages/eslint-config';
  const BAN_SOURCE_FILES = LINTABLE_TRACKED.files.filter((f) => f.startsWith(`${PKG_DIR}/src/`));

  // Derived from the package's own export map, not a hardcoded pair: these are
  // exactly the specifiers another config can import, so a new entry point is
  // covered without anyone remembering to widen a list. Conditional (object)
  // targets are skipped rather than guessed at — there are none today, and one
  // added later shows up as a missing case here rather than as a silent pass.
  const ENTRY_POINTS = Object.values(
    JSON.parse(readFileSync(join(REPO_ROOT, PKG_DIR, 'package.json'), 'utf8')).exports ?? {},
  )
    .filter((target) => typeof target === 'string')
    .map((target) => `${PKG_DIR}/${target.replace(/^\.\//, '')}`)
    .sort();

  /** @type {ESLint} */
  let eslint;
  beforeAll(() => {
    eslint = new ESLint({ cwd: join(REPO_ROOT, PKG_DIR) });
  });

  it('has a case for every entry point another config can import', () => {
    // A vacuous-pass guard: an empty case list makes the it.each below disappear
    // and the suite reports green having pointed at nothing at all.
    expect(ENTRY_POINTS.length, 'the package exports no string target to lint').toBeGreaterThan(0);
    for (const entry of ENTRY_POINTS) {
      expect(BAN_SOURCE_FILES, `${entry} is exported but is not a tracked lintable file`).toContain(
        entry,
      );
    }
  });

  it.each(BAN_SOURCE_FILES)(
    'reports every network form at %s',
    async (file) => {
      const abs = join(REPO_ROOT, ...file.split('/'));
      expect(await eslint.isPathIgnored(abs), `${file} is excluded by an eslint ignore`).toBe(
        false,
      );

      // Half one, at the EXACT path: the cascade this package's own config
      // produces for the real file has to carry all four bans.
      const resolved = await eslint.calculateConfigForFile(abs);
      expect(
        resolved,
        `eslint resolved no config block for ${file}, so the ban reaches its own source through ` +
          'nothing',
      ).toBeTruthy();
      const fired = firedRuleIds(NETWORK_SNIPPET, networkRulesOf(resolved));
      for (const key of KEYS) {
        expect(fired, `${file} :: ${key}`).toContain(key);
      }

      // Half two: the real bytes have to PARSE under that cascade. src/ is plain
      // JS reached through the package tsconfig's `allowJs`, so the type-aware
      // parser has a program for it — but a change to that tsconfig's `include`
      // would leave the ban structurally wired over a file that reports a fatal
      // error and NO rule violations, which is half one describing a cascade that
      // never gets to run.
      const [real] = await eslint.lintFiles([abs]);
      expect(
        (real?.messages ?? []).filter((m) => m.fatal).map((m) => m.message),
        `${file} did not parse, so no rule could run against it whatever the cascade resolves`,
      ).toEqual([]);
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
      const invocations = packageLintInvocations(
        /** @type {{ lintScript: string }} */ (pkg).lintScript,
      );
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
      const invocation = packageLintInvocations(lintScript).find((i) =>
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
          invocationsCoverFile(packageLintInvocations(lintScript), PROBE_FILE),
          `the real script reads as not covering ${PROBE_FILE}, so the flagged read below would ` +
            'match it for the wrong reason',
        ).toBe(true);
        expect(
          invocationsCoverFile(packageLintInvocations(mutatedScript), PROBE_FILE),
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
