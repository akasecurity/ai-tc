import { execFileSync } from 'node:child_process';
import { existsSync, globSync, readFileSync } from 'node:fs';
import { dirname, join, posix, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ESLint } from 'eslint';

// The one reader of this repo's `lint` scripts, shared by the two suites next to
// it. Both ask the same question of the same strings and act on the answer in
// different ways — effective-config.test.js asks which PATHS a green run lints,
// no-network.test.js asks which CONFIGS it lints them under — so a second reader
// would be two models of one shell string, free to disagree about what runs. A
// file could then read as covered by one and be audited by neither.
//
// Everything here is pure over its inputs except the four workspace readers at
// the bottom (which read the real manifest / the real checkout) and
// resolveInvocationConfig (which asks ESLint itself). That split is deliberate:
// the derivations are unit-testable on synthetic input, and the one question
// with a real answer is put to the tool that owns it rather than modelled.

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');

/** git reports posix paths on every platform; globSync and join yield native ones. */
export const toPosix = (p) => p.split(sep).join('/');

// eslint flags that consume the NEXT argument, so its value is not mistaken for
// a lint target (`-c eslint.scripts.config.mjs scripts` targets scripts, not the
// config file). Boolean flags are skipped by the leading-dash test alone.
export const ESLINT_VALUE_FLAGS = new Set([
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
// fault-injection suite; these live in package.json, where ESLint's own API
// never sees them.
//
// `--ignore-path` is listed for completeness rather than because it works: under
// flat config the CLI rejects the flag outright ("Invalid option
// '--ignore-path'", exit 2), so an invocation carrying one lints NOTHING. It is
// modelled as excluding everything, which is what that run really covers.
export const IGNORE_VALUE_FLAGS = new Set(['--ignore-pattern', '--ignore-path']);

// The flags that name the config an invocation runs under. Both spellings of
// both, and both are read: an unread config flag does not cost a target, it
// costs the whole question of WHICH RULES that run enforced — the config drops
// out of the opt-out audit while ESLint honours it exactly like the others.
export const CONFIG_VALUE_FLAGS = new Set(['-c', '--config']);

/** Every value flag whose value this parser keeps rather than skips. */
const READ_VALUE_FLAGS = new Set([...CONFIG_VALUE_FLAGS, ...IGNORE_VALUE_FLAGS]);

export const unquote = (token) => token.replace(/^['"]|['"]$/g, '');

/**
 * Every eslint invocation in a `lint` script, in order — its `-c`/`--config`
 * override (undefined when the invocation uses ordinary config lookup), whether
 * `--no-config-lookup` suppressed that lookup, its positional path targets, and
 * the ignore flags that subtract from them. Kept as invocations rather than one
 * flat target list for three reasons. The fault-injection runs have to reproduce
 * ONE of them faithfully: cli lints `src test *.config.*` under eslint.config.mjs
 * and `scripts` under eslint.scripts.config.mjs, so running the flattened target
 * list under either config lints half the package with the wrong ruleset. An
 * ignore flag binds to the single eslint call it sits on, so flattening would let
 * one invocation's exclusion silently narrow another's targets. And a config is
 * a property of one call, not of the script — which is what makes an odd-named
 * config discoverable at all.
 *
 * Both spellings of every flag this parser READS are handled — `-c <file>`,
 * `--config <file>`, `--config=<file>` and the same three for the ignores —
 * because for all of them the fallthrough costs the thing being modelled: an
 * unparsed `--ignore-pattern=<glob>` leaves a file reading as covered while
 * eslint skips it, and an unparsed `--config=<file>` leaves a real ruleset
 * outside the opt-out audit. Flags this parser does not read still fall through
 * as plain flags, which costs a value it never wanted.
 *
 * A config flag with no value after it leaves `configName` undefined, so the
 * invocation reads as using ordinary lookup. eslint refuses such a command
 * outright, so that run lints nothing and `pnpm lint` is already red; crediting
 * it with the package's own config audits one config more than the broken run
 * reaches, which is the harmless direction.
 * @param {string} lintScript
 * @returns {{
 *   configName: string | undefined, noConfigLookup: boolean, targets: string[],
 *   ignorePatterns: string[], ignorePaths: string[],
 * }[]}
 */
export function eslintInvocations(lintScript) {
  const invocations = [];
  for (const command of lintScript.split(/&&|\|\||;/)) {
    const tokens = command.match(/[^\s"']+|"[^"]*"|'[^']*'/g) ?? [];
    const start = tokens.findIndex((t) => /(?:^|\/)eslint$/.test(unquote(t)));
    if (start === -1) continue;
    /**
     * @type {{
     *   configName: string | undefined, noConfigLookup: boolean, targets: string[],
     *   ignorePatterns: string[], ignorePaths: string[],
     * }}
     */
    const invocation = {
      configName: undefined,
      noConfigLookup: false,
      targets: [],
      ignorePatterns: [],
      ignorePaths: [],
    };
    // Repeatable: every ignore flag on one invocation ADDS to its set, so
    // reading only the last would drop the earlier exclusions. A flag left with
    // no value records '', which the coverage predicates read as excluding
    // everything — eslint itself refuses such a command, so a script that lints
    // nothing must not parse as one that lints all of it. A repeated config flag
    // is the opposite shape: eslint keeps the LAST one, so this does too.
    const setValue = (flag, value) => {
      if (CONFIG_VALUE_FLAGS.has(flag)) {
        if (value !== '') invocation.configName = value;
        return;
      }
      (flag === '--ignore-path' ? invocation.ignorePaths : invocation.ignorePatterns).push(value);
    };
    for (let i = start + 1; i < tokens.length; i++) {
      const token = unquote(tokens[i]);
      if (token.startsWith('-')) {
        const eq = token.indexOf('=');
        const name = eq === -1 ? token : token.slice(0, eq);
        // The one boolean flag that changes which config a run uses: with it,
        // an invocation carrying no `-c` runs under NO config file at all
        // rather than under the one ordinary lookup would find.
        if (name === '--no-config-lookup') {
          invocation.noConfigLookup = true;
          continue;
        }
        if (eq !== -1 && READ_VALUE_FLAGS.has(name)) {
          // The tokenizer splits `--flag='<value>'` into the flag with a
          // trailing `=` plus the quoted value, so an empty inline value takes
          // the next token.
          const inline = token.slice(eq + 1);
          setValue(name, inline === '' ? unquote(tokens[++i] ?? '') : inline);
          continue;
        }
        if (ESLINT_VALUE_FLAGS.has(token)) {
          const next = tokens[i + 1];
          if (READ_VALUE_FLAGS.has(token)) setValue(token, next === undefined ? '' : unquote(next));
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
 * Every walk goes through this — the scripts a script chains AND the eslint calls
 * it makes directly. Reading the two by different rules is what lets
 * `eslint <targets> || eslint <other targets>` read as covering both while the
 * second only runs once the first has already failed, which is a file reported as
 * linted that no green run ever lints.
 * @param {string} script
 * @returns {string[]} the segments that run unconditionally
 */
export const unconditionalSegments = (script) =>
  script.split('&&').filter((part) => !/\||;|&|#/.test(part));

/**
 * The other package scripts a script body runs unconditionally.
 * @param {string} script
 * @returns {string[]} the script names it runs
 */
export function scriptReferences(script) {
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

// The root script the gates run: lefthook's pre-push hook, the CI lint step and
// both release workflows all invoke `pnpm lint`. Coverage is walked FROM it, not
// collected from every script in the manifest, because an invocation nothing runs
// covers nothing: a conventional `"lint:fix": "eslint . --fix"` sitting in the
// manifest would otherwise satisfy every check below however narrow the real pass
// got, and the guards would go green while the ban stopped reaching these files.
export const ROOT_LINT_ENTRY_SCRIPT = 'lint';

/**
 * Every eslint invocation `pnpm <entry>` really runs, following the root scripts
 * it chains. Read out of the script BODIES rather than by the name of the pass,
 * so renaming `lint:root` cannot blind this — a rename has to update the caller,
 * which this walk reads. Deleting the chain, or making it conditional, empties
 * the list instead.
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
export function rootLintInvocations(scripts, entry = ROOT_LINT_ENTRY_SCRIPT) {
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

/**
 * Every eslint invocation a package's `lint` script actually runs on a green
 * pass. One helper rather than a bare `eslintInvocations(lintScript)` at each
 * call site, for the same reason coveringInvocation exists: the coverage check
 * and the fault injection that reproduces it must read the script by ONE rule,
 * or a script whose segments disagree could be blessed by one and reproduced
 * from the other. `unconditionalSegments` is that rule.
 * @param {string} lintScript
 */
export const packageLintInvocations = (lintScript) =>
  unconditionalSegments(lintScript).flatMap(eslintInvocations);

// --- Which config each invocation runs under ---------------------------------

/**
 * Every eslint invocation a green `pnpm <entry>` runs anywhere in the workspace,
 * each paired with the directory it runs in. The repo-root pass runs at the repo
 * root; `turbo run lint` drives each package's own `lint` script with that
 * package as the working directory, which is what decides where a bare
 * `eslint src` looks for its config.
 *
 * Pure over its inputs so the failure paths are testable on synthetic manifests;
 * the real tree is healthy and produces none by construction.
 * @param {{
 *   rootScripts: Record<string, unknown> | undefined,
 *   packages: { dir: string, lintScript: string }[],
 *   entry?: string,
 * }} input
 * @returns {{ cwd: string, invocation: ReturnType<typeof eslintInvocations>[number] }[]}
 */
export function lintPassInvocations({ rootScripts, packages, entry = ROOT_LINT_ENTRY_SCRIPT }) {
  const found = rootLintInvocations(rootScripts, entry).map((invocation) => ({
    cwd: '',
    invocation,
  }));
  for (const { dir, lintScript } of packages) {
    for (const invocation of packageLintInvocations(lintScript)) {
      found.push({ cwd: toPosix(dir), invocation });
    }
  }
  return found;
}

/**
 * The config file one invocation runs under, as a repo-relative posix path, or
 * undefined when it runs under none.
 *
 * Put to ESLint rather than modelled. Ordinary flat-config lookup is a search
 * order over six filenames that walks UP from the working directory, and any
 * model of it is a second implementation free to drift from the one that
 * actually decides — the failure being that a config ESLint honours reads as
 * belonging to no lint pass and drops out of the audit, which is the whole
 * defect this derivation exists to close. `overrideConfigFile` is the API
 * spelling of the two flags: a path for `-c <file>`, `true` for
 * `--no-config-lookup`.
 *
 * A `-c` naming a file that does not exist comes back as that path, not as
 * undefined, so a referenced-but-missing config is reported rather than silently
 * dropped.
 * @param {{ cwd: string, invocation: { configName?: string, noConfigLookup: boolean } }} entry
 * @param {string} repoRoot
 * @returns {Promise<string | undefined>}
 */
export async function resolveInvocationConfig({ cwd, invocation }, repoRoot = REPO_ROOT) {
  const cwdAbs = cwd ? resolve(repoRoot, ...cwd.split('/')) : repoRoot;
  // `resolve`, not `join`: a `-c` may name an absolute path, which join would
  // graft onto the working directory instead of honouring.
  const overrideConfigFile = invocation.configName
    ? resolve(cwdAbs, ...invocation.configName.split('/'))
    : invocation.noConfigLookup
      ? true
      : undefined;
  const found = await new ESLint({
    cwd: cwdAbs,
    ...(overrideConfigFile === undefined ? {} : { overrideConfigFile }),
  }).findConfigFile();
  return found === undefined ? undefined : toPosix(relative(repoRoot, found));
}

// A tracked file whose NAME reads as an ESLint flat config, matched on the
// basename alone. This is the DISCOVERY half, and it answers a different
// question from the derivation above: which files a reader would take for a lint
// surface, whether or not any invocation names one. The difference between the
// two sets is the drift — a config no pass references enforces nothing while
// looking exactly like the ones that do, and a config a pass references under an
// unconventional name enforces everything while matching no filename convention.
//
// Deliberately wider than the two conventional names and deliberately narrower
// than "any file a `-c` could name": a config called something with no `eslint`
// in it at all is still AUDITED (the derivation finds it through the invocation
// that names it) but is not DISCOVERED, so it cannot be reported as dead. That
// is the limit of what a name can tell you, and it falls on the quiet side of a
// file nothing runs.
export const ESLINT_CONFIG_BASENAME = /eslint.*\.config\.[cm]?[jt]s$/;

// --- The real workspace ------------------------------------------------------

/**
 * Parse the package globs declared under `packages:` in a pnpm-workspace.yaml
 * document, without a YAML dependency. Pure over its input string so the parse —
 * the most fragile part of this module — is unit-tested on synthetic YAML rather
 * than only against the one real on-disk manifest. Walks line by line: enter the
 * block at a bare `packages:` line, collect each `- <scalar>` sequence entry
 * (quoted or bare), tolerate blank and comment lines inside the block, and stop at
 * the next column-0 key. Flow style (`packages: [ … ]`) is intentionally NOT
 * parsed — it yields an empty list, which the vacuous-pass guards turn into a loud
 * failure rather than a silent under-enumeration. An exclusion glob throws for the
 * same reason: globSync would treat `!pkg` as a literal pattern that matches
 * nothing, leaving the excluded directory in the enumeration under a misleading
 * failure.
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
    if (!m) continue;
    const glob = m[1].trim();
    if (glob.startsWith('!')) {
      throw new Error(
        `pnpm-workspace.yaml declares the exclusion glob "${glob}", which this parser does not ` +
          'model. Teach parseWorkspaceGlobs/workspacePackageDirs to honour negation before ' +
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
export function workspaceGlobs() {
  return parseWorkspaceGlobs(readFileSync(join(REPO_ROOT, 'pnpm-workspace.yaml'), 'utf8'));
}

/**
 * Every workspace package directory on disk, resolved from pnpm-workspace.yaml:
 * expand each glob and keep the directories that hold a package.json. Native
 * separators, as globSync yields them.
 * @returns {string[]}
 */
export function workspacePackageDirs() {
  return [
    ...new Set(
      workspaceGlobs()
        .flatMap((g) => globSync(g, { cwd: REPO_ROOT }))
        .filter((rel) => existsSync(join(REPO_ROOT, rel, 'package.json'))),
    ),
  ].sort();
}

/**
 * A workspace package's parsed manifest.
 * @param {string} dir package directory, relative to the repo root
 */
export const readPackageManifest = (dir) =>
  JSON.parse(readFileSync(join(REPO_ROOT, dir, 'package.json'), 'utf8'));

/**
 * Every workspace package's `lint` script, in the shape lintPassInvocations
 * takes. A package with no `lint` script contributes an empty string, which
 * parses to no invocations — turbo skips such a package silently, and that hole
 * is the per-package structural guard's business, not this one's.
 * @returns {{ dir: string, lintScript: string }[]}
 */
export const workspaceLintScripts = () =>
  workspacePackageDirs().map((dir) => ({
    dir,
    lintScript: readPackageManifest(dir).scripts?.lint ?? '',
  }));

/** The root manifest's `scripts` block. */
export const rootScripts = () =>
  JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')).scripts;

/**
 * Every git-tracked file, in repo-relative posix form. Tracked-ness is what
 * separates a real file from a build artifact or a scratch file someone left
 * behind, so every audit that asks "does the tree really hold this?" starts
 * here — and from ONE reader, for the same reason the invocation walk is one:
 * two copies of this call would be free to disagree about what the tree holds.
 * @returns {string[]}
 */
export function trackedFiles() {
  try {
    return execFileSync('git', ['ls-files'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      maxBuffer: 64 << 20,
    })
      .split('\n')
      .filter(Boolean);
  } catch (cause) {
    throw new Error(
      'Could not list tracked files with `git ls-files`. This guard audits the real workspace ' +
        'layout, so it must run inside a git checkout.',
      { cause },
    );
  }
}

/**
 * Every git-tracked file whose basename reads as an ESLint flat config, in
 * repo-relative posix form.
 * @returns {string[]}
 */
export function trackedEslintConfigFiles() {
  return trackedFiles()
    .filter((file) => ESLINT_CONFIG_BASENAME.test(posix.basename(file)))
    .sort();
}

// The extensions ESLint actually lints here. This is what separates a code
// directory from a data one: packages/schema/drizzle holds only .sql/.json
// migrations, so there is nothing there for the bans to guard, while
// plugins/claude-code/eval ships a real .ts file and belongs behind them.
//
// It lives beside trackedFiles() for the same reason that walk does. Two audits
// asking "which files does the workspace lint?" off two copies of this pattern
// would be free to disagree, and the disagreement is silent in the worst
// direction: a file one audit counts as source and the other does not is a file
// covered by one guard and inventoried by neither.
export const LINTABLE_EXT = /\.[cm]?[jt]sx?$/;

/**
 * Every git-tracked file ESLint would lint, in repo-relative posix form.
 * @returns {string[]}
 */
export const lintableTrackedFiles = () => trackedFiles().filter((f) => LINTABLE_EXT.test(f));
