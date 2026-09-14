/**
 * `test/helpers/remove-tree.ts` exists because a bare
 * `rmSync(dir, { recursive: true, force: true })` can meet EPERM/EBUSY/EACCES on
 * Windows when the directory it is removing was just touched by a real,
 * out-of-process actor — a `LocalDatabase` whose `-wal`/`-shm` sidecars outlive
 * its `close()` by a moment, or a spawned child (`execFileSync`/`spawnSync`/
 * `spawn`, or a PATH shim it ran from) that has not yet released a handle. A
 * teardown that meets that after every assertion in the test already passed
 * reads as the test being broken, on the one leg it never actually failed on.
 *
 * That pattern was fixed at every site a sweep of the tree found, but nothing
 * stopped a NEW bare teardown of that same shape from being written tomorrow —
 * so this asserts the pattern rather than trusting review to keep catching it.
 *
 * What counts as the pattern, precisely: a tracked test file's own recursive
 * `rmSync`, correlated with an actor that touched the tree it removes. Three
 * parts:
 *
 *   WHAT IS REMOVED. A named identifier (`rmSync(base, …)`), or a LIST of trees —
 *   drained in the argument (`rmSync(dirs.pop() ?? '', …)`) or walked by a
 *   for-of (`for (const dir of dirs) rmSync(dir, …)`). A for-of binding is its
 *   own nearest declaration, so correlating on the binding finds nothing; a list
 *   removal is correlated on the list instead, expanded to what it holds —
 *   values pushed into it, the local factory doing the pushing, and names bound
 *   from calls to that factory. Every path declared as `join(<one of those>, …)`
 *   counts as well, since it goes WITH the tree. That walk is downward only,
 *   never from the removed tree up to its parent.
 *
 *   WHERE TO LOOK. The block the identifier (or list) was declared in, walked
 *   from that block's start to its end, not merely up to the removal (a
 *   `beforeEach` opens the store; a sibling `afterEach` removes it). A bare
 *   property access (`this.storeDir`) or an identifier this file never sees
 *   declared is scoped to the whole file — the safe direction to be wrong in:
 *   it can over-match and read a real exception's site correctly, never quietly
 *   clear a real one.
 *
 *   WHAT TOUCHED IT. An `openLocalDatabase(…)` whose arguments name one of those
 *   names; a real spawn — or a name imported from a spawning TEST helper — whose
 *   own argument list names one; or a memoised-store release (`closeStore`,
 *   `releaseLocalStore`, `dropMemoisedDb`) anywhere in that scope, because a
 *   page render opens the store under a redirected home without the file ever
 *   naming `openLocalDatabase`.
 *
 * Four things this deliberately does NOT flag, because the risk it exists for
 * does not apply to them:
 *
 *   - a single-file, non-recursive `rmSync` — `{ recursive: true }` must be
 *     present in the call's own options, textually, or this never matches it;
 *   - product code — anything outside a `test`/`tests` directory or a
 *     `.test.`/`.spec.` file, using the same classifier
 *     `test-only-seam.test.js` uses, for the reason it gives there;
 *   - `removeTree`/`removeTrees`'s OWN implementation, wherever it is
 *     defined — this repo carries `test/helpers/remove-tree.ts` at the root
 *     plus one package-walled peer copy in
 *     `packages/persistence/test/helpers/temp-store.ts`, and both bodies
 *     literally are the `rmSync(dir, { recursive: true, … })` call this file
 *     is looking for. Excluded STRUCTURALLY — a call sitting directly inside a
 *     function named `removeTree`/`removeTrees` — rather than by listing the
 *     two paths, so a third peer copy needs no edit here to stay unflagged;
 *   - a deliberate, reasoned exception, recorded in `DOCUMENTED_EXCEPTIONS`
 *     below with why swallowing a win32 EPERM there would be wrong.
 *
 * The detector is regex-and-brace-counting, not a parser, so it inherits the
 * usual blind spots (a brace inside a string or template literal is counted as
 * real; a path built by anything but `join` is not followed). Nothing here
 * relies on that being wrong in a direction that hides a real site —
 * `DOCUMENTED_EXCEPTIONS` is an exact set checked against what the tree actually
 * holds, so a detector regression that stops seeing a real risky site fails on
 * the exact-set count either way.
 */
import { readFileSync } from 'node:fs';
import { join, posix } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT, trackedFiles } from './helpers/lint-invocations.js';

// This walks every tracked test-like file in the workspace looking for a
// pattern, which is the same shape of cost `test-only-seam.test.js` budgets
// for in this same package — see its comment for why the number is what it
// is.
const TREE_WALK_TIMEOUT_MS = 30_000;

// A floor on a recorded reason, not a quality bar — long enough that `''` or a
// placeholder cannot pass, short enough that it never fights a real one.
const MIN_REASON_CHARS = 20;

/**
 * True for a path this workspace treats as test code — a peer copy of
 * `test-only-seam.test.js`'s classifier in this same package, kept local
 * rather than imported because a one-line predicate does not carry its own
 * import worth naming, and copying keeps each guard's fault-injection tests
 * pinned against the exact predicate that guard runs.
 * @param {string} file repo-relative posix path
 */
function isTestFile(file) {
  const segments = file.split('/');
  return (
    segments.slice(0, -1).some((s) => s === 'test' || s === 'tests') ||
    /\.(test|spec)\./.test(posix.basename(file))
  );
}

/**
 * Source with comments removed, so a mention in prose is never read as a call.
 * Block comments first, so a `//` inside one does not survive as code once the
 * block markers are gone; `[^:]` keeps a real call sharing a line with a
 * `'https://…'` literal from being truncated at the URL's own slashes.
 * @param {string} source
 */
function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/**
 * An identifier, escaped for interpolation into a RegExp.
 * @param {string} ident
 */
function escapeIdent(ident) {
  return ident.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * The start index of the innermost `{ … }` enclosing `pos`, or 0 for module
 * scope. A plain brace-depth scan — it does not tokenize strings or template
 * literals, so a literal brace in either is counted as a real one; the known
 * limit `harness-adoption.test.ts` already accepts for the same technique.
 * @param {string} code
 * @param {number} pos
 */
function enclosingBlockStart(code, pos) {
  const stack = [];
  for (let i = 0; i < pos; i++) {
    if (code[i] === '{') stack.push(i);
    else if (code[i] === '}') stack.pop();
  }
  return stack.length ? stack[stack.length - 1] + 1 : 0;
}

/**
 * The index just past the `}` matching the `{` at `blockStart - 1`, or the end
 * of the file for module scope (`blockStart === 0`).
 * @param {string} code
 * @param {number} blockStart
 */
function matchingBlockEnd(code, blockStart) {
  if (blockStart === 0) return code.length;
  let depth = 1;
  for (let i = blockStart; i < code.length; i++) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return code.length;
}

/**
 * The `[start, end)` span of the block `ident` was declared in — the nearest
 * preceding `let`/`const`/`var ident`, widened to its own enclosing block, so
 * a store opened in a `beforeEach` is visible to a bare removal sitting in the
 * sibling `afterEach` (both children of the same `describe`), without also
 * reaching into an unrelated `describe` two thousand lines away that happens
 * to reuse the same variable name. A dotted identifier (`this.storeDir`) or
 * one this file never declares gets the whole file — conservative, not
 * precise, and safe in the direction that matters here (see the file header).
 * @param {string} code
 * @param {string} ident
 * @param {number} beforePos
 * @returns {[number, number]}
 */
function declarationScope(code, ident, beforePos) {
  if (ident.includes('.')) return [0, code.length];
  const declRe = new RegExp(`\\b(?:let|const|var)\\s+${escapeIdent(ident)}\\b`, 'g');
  let m;
  let last = -1;
  while ((m = declRe.exec(code))) {
    if (m.index >= beforePos) break;
    last = m.index;
  }
  if (last === -1) return [0, code.length];
  const start = enclosingBlockStart(code, last);
  return [start, matchingBlockEnd(code, start)];
}

/**
 * `names` plus every identifier the window declares as a path INSIDE one of
 * them — `const homeDir = join(dir, 'home')`. Anything under the removed tree is
 * removed WITH it, so a child holding `homeDir` blocks `rmSync(dir, …)` exactly
 * as one holding `dir` would; correlating on identifier identity alone missed
 * that, because the spawn names the descendant and the teardown the ancestor.
 * Transitive (a path under a path under the tree), and DOWNWARD only — nothing
 * here walks from the removed tree to its parent, which would re-open the
 * unrelated-sibling false positive the argument-list rule exists to close.
 * @param {string} window
 * @param {Set<string>} names
 * @returns {Set<string>}
 */
function withPathsUnder(window, names) {
  const out = new Set(names);
  for (let pass = 0; pass < 6; pass++) {
    let grew = false;
    for (const name of [...out]) {
      const re = new RegExp(
        `(?:\\b(?:let|const|var)\\s+)?\\b([A-Za-z_$][\\w$]*)\\s*(?::[^=;]*)?=\\s*join\\s*\\(\\s*${escapeIdent(name)}\\b`,
        'g',
      );
      let m;
      while ((m = re.exec(window))) {
        if (!out.has(m[1])) {
          out.add(m[1]);
          grew = true;
        }
      }
    }
    if (!grew) break;
  }
  return out;
}

/**
 * `list` plus what the window puts INTO it — `list.push(y)`, the local factory
 * that does the pushing, and anything bound from a call to that factory. A suite
 * that collects its temp trees in an array removes them under a name no store
 * open or spawn ever sees (a loop binding, a `.pop()`), so the array is the only
 * stable handle on the collection; these are the names its members are really
 * passed around under.
 * @param {string} window
 * @param {string} list
 * @returns {Set<string>}
 */
function withListMembers(window, list) {
  const out = new Set([list]);
  /** @type {Set<string>} */
  const factories = new Set();
  const pushRe = new RegExp(
    `\\b${escapeIdent(list)}\\s*\\.\\s*push\\s*\\(\\s*([A-Za-z_$][\\w$]*)`,
    'g',
  );
  let m;
  while ((m = pushRe.exec(window))) {
    out.add(m[1]);
    // The name of the function doing the pushing, read from its block's
    // preface the way `isRemoveTreeDefinition` reads one.
    const blockStart = enclosingBlockStart(window, m.index);
    const preface = window.slice(Math.max(0, blockStart - 200), blockStart);
    const nameRe =
      /\bfunction\s+([A-Za-z_$][\w$]*)|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]*)?=\s*(?:async\s*)?\(/g;
    let nm;
    let enclosing;
    while ((nm = nameRe.exec(preface))) enclosing = nm[1] ?? nm[2];
    if (enclosing) {
      out.add(enclosing);
      factories.add(enclosing);
    }
  }
  for (const factory of factories) {
    const bindRe = new RegExp(
      `\\b(?:let|const|var)\\s+([A-Za-z_$][\\w$]*)\\s*(?::[^=;]*)?=\\s*${escapeIdent(factory)}\\s*\\(`,
      'g',
    );
    let b;
    while ((b = bindRe.exec(window))) out.add(b[1]);
  }
  return out;
}

/**
 * The identifier of the list a `for (const ident of LIST…)` before `pos`
 * iterates, or undefined when `ident` is not a loop binding. A for-of binding IS
 * its own nearest-preceding declaration, so `declarationScope` collapses to the
 * teardown hook's own body and correlates against nothing; the list is the name
 * the rest of the file actually uses.
 * @param {string} code
 * @param {string} ident
 * @param {number} pos
 * @returns {string | undefined}
 */
function loopListRoot(code, ident, pos) {
  const re = new RegExp(
    `\\bfor\\s*\\(\\s*(?:const|let|var)\\s+${escapeIdent(ident)}\\s+of\\s+([A-Za-z_$][\\w$]*)`,
    'g',
  );
  let m;
  let root;
  while ((m = re.exec(code))) {
    if (m.index >= pos) break;
    root = m[1];
  }
  return root;
}

/**
 * Whether `pos` sits directly inside a function named `removeTree`/`removeTrees`.
 * @param {string} code
 * @param {number} pos
 */
function isRemoveTreeDefinition(code, pos) {
  const blockStart = enclosingBlockStart(code, pos);
  const preface = code.slice(Math.max(0, blockStart - 200), blockStart);
  return /\bfunction\s+removeTrees?\s*\(/.test(preface);
}

// The calls that let go of a memoised store. A page render opens the store under
// a redirected home through the app's own module, so a file whose teardown
// releases one never names `openLocalDatabase` — the release is the trace.
const STORE_RELEASE_RE = /\b(?:closeStore|releaseLocalStore|dropMemoisedDb)\s*\(/;

/**
 * Every recursive `rmSync` in `code` whose removed tree is, within its own
 * declaration scope, handed to `openLocalDatabase(…)`, named inside a real
 * spawn's argument list (or that of a spawning test helper in
 * `spawningImports`), or sits in a scope that releases a memoised store — the
 * out-of-process actors a bare removal can race. Excludes a call sitting inside
 * `removeTree`/`removeTrees`'s own body. See the file header for what "the
 * removed tree" covers.
 * @param {string} code comments already stripped
 * @param {Set<string>} [spawningImports] names this file imports from a test
 *   helper that spawns on its caller's behalf
 * @returns {{ ident: string, pos: number }[]}
 */
function riskyBareRemovals(code, spawningImports = new Set()) {
  const found = [];
  // Either a bare/dotted identifier, or a drain of an array of trees
  // (`dirs.pop() ?? ''`) — which is a CALL, so the identifier form alone never
  // even considered the site.
  const callRe =
    /\brmSync\s*\(\s*(?:([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)|([A-Za-z_$][\w$]*)\s*\.\s*(?:pop|shift|splice)\s*\([^)]*\)[^,]*)\s*,\s*\{([^}]*)\}\s*\)/g;
  let m;
  while ((m = callRe.exec(code))) {
    const [, direct, drained, opts] = m;
    if (!/recursive\s*:\s*true/.test(opts)) continue;
    const pos = m.index;
    if (isRemoveTreeDefinition(code, pos)) continue;

    // A for-of binding is its own nearest declaration, so correlate on the
    // LIST it iterates rather than on the binding.
    let ident = direct ?? drained;
    let isList = drained !== undefined;
    if (direct !== undefined && !direct.includes('.')) {
      const root = loopListRoot(code, direct, pos);
      if (root !== undefined) {
        ident = root;
        isList = true;
      }
    }

    const [scopeStart, scopeEnd] = declarationScope(code, ident, pos);
    const window = code.slice(scopeStart, scopeEnd);

    // The names that stand for the tree being removed: the identifier itself,
    // what a list of trees holds, and every path declared INSIDE any of them.
    const names = withPathsUnder(
      window,
      isList ? withListMembers(window, ident) : new Set([ident]),
    );

    let touched = STORE_RELEASE_RE.test(window);

    for (const name of names) {
      if (touched) break;
      if (new RegExp(`\\bopenLocalDatabase\\s*\\([^)]*\\b${escapeIdent(name)}\\b`).test(window)) {
        touched = true;
      }
    }

    // A real spawn correlates only when one of those names appears inside that
    // CALL's own argument list (its cwd, its env, an argv entry) — not merely
    // somewhere else in the same scope, which is what let `home` in one
    // unrelated `it()` read as spawn-touched because a distant sibling `it()`
    // also spawned something. `[\s\S]{0,400}` bounds the argument-list window;
    // every real call site here fits well inside it. `spawningImports` adds the
    // test helpers that spawn on the caller's behalf, so a spawn that moved one
    // file away is still seen.
    const callees = ['execFileSync', 'spawnSync', 'spawn', ...spawningImports];
    const spawnArgsRe = new RegExp(
      `\\b(?:${callees.map((c) => escapeIdent(c)).join('|')})\\s*\\(([\\s\\S]{0,400}?)\\)`,
      'g',
    );
    let sm;
    while (!touched && (sm = spawnArgsRe.exec(window))) {
      const args = sm[1];
      for (const name of names) {
        if (new RegExp(`\\b${escapeIdent(name)}\\b`).test(args)) {
          touched = true;
          break;
        }
      }
    }

    if (touched) found.push({ ident, pos });
  }
  return found;
}

// Memoized for the module's life — nothing here mutates the tree mid-run, and
// several `it()`s below ask the same question of the same files.
/** @type {string[] | undefined} */
let candidateFilesCache;
/** @type {Map<string, string>} */
const readCache = new Map();

/** Every tracked `.ts`/`.tsx` file this workspace treats as test code. */
function candidateFiles() {
  candidateFilesCache ??= trackedFiles()
    .filter((f) => /\.tsx?$/.test(f))
    .filter(isTestFile)
    .sort();
  return candidateFilesCache;
}

/** @param {string} file */
function read(file) {
  let source = readCache.get(file);
  if (source === undefined) {
    source = readFileSync(join(REPO_ROOT, ...file.split('/')), 'utf8');
    readCache.set(file, source);
  }
  return source;
}

/**
 * Local names a file imports from a relative TEST HELPER whose own text spawns.
 * The spawn a bare teardown races need not sit in the test file: a shared helper
 * that runs children on the caller's behalf (`runConcurrentSettingsWriters(base,
 * …)`, `assertShimResolves(…, { cwd })`) puts it one import away, where
 * correlating on this file's text alone finds nothing at all. Restricted to a
 * helper the tree already treats as test code — reaching into `src/` would make
 * every call to any product function that spawns somewhere read as a spawn of
 * this directory.
 * @param {string} file repo-relative posix path
 * @param {string} code comments already stripped
 * @returns {Set<string>}
 */
function spawningTestHelperImports(file, code) {
  /** @type {Set<string>} */
  const names = new Set();
  const importRe = /\bimport\s+\{([^}]*)\}\s*from\s*['"](\.[^'"]*)['"]/g;
  let m;
  while ((m = importRe.exec(code))) {
    const [, clause, specifier] = m;
    const target = posix.normalize(posix.join(posix.dirname(file), specifier));
    if (!isTestFile(target)) continue;
    let helper;
    try {
      helper = stripComments(read(target));
    } catch {
      continue;
    }
    if (!/\b(?:execFileSync|spawnSync|spawn)\s*\(/.test(helper)) continue;
    for (const entry of clause.split(',')) {
      const name = entry
        .trim()
        .replace(/^type\s+/, '')
        .split(/\s+as\s+/)
        .pop()
        ?.trim();
      if (name && /^[A-Za-z_$][\w$]*$/.test(name)) names.add(name);
    }
  }
  return names;
}

/**
 * The risky removals in one tracked file, with that file's spawning imports.
 * @param {string} file
 */
function riskyRemovalsIn(file) {
  const code = stripComments(read(file));
  return riskyBareRemovals(code, spawningTestHelperImports(file, code));
}

/** `"<file>::<ident>"` for every risky bare removal the tree currently holds. */
function riskySiteKeys() {
  const keys = [];
  for (const file of candidateFiles()) {
    for (const { ident } of riskyRemovalsIn(file)) {
      keys.push(`${file}::${ident}`);
    }
  }
  return keys.sort();
}

/**
 * Real, reasoned exceptions — a site this guard's predicate flags, kept bare
 * on purpose because the Windows-only risk `removeTree` tolerates cannot
 * actually occur there. Not a floor: a new site landing bare and unreasoned
 * fails the exact-set assertion below, exactly as a new hand-rolled store
 * would fail `harness-adoption.test.ts`.
 */
const DOCUMENTED_EXCEPTIONS = {
  'cli/test/lib/external-dispatch.test.ts::binDir':
    "the test is gated behind it.runIf(process.platform !== 'win32'), so it never runs on " +
    'the one platform removeTree exists to tolerate a sharing violation on',
  'packages/local-ops/test/exec-quoting.test.ts::dir':
    "the whole describe is describe.skipIf(process.platform === 'win32'), and vitest does not " +
    'run a skipped suite’s afterAll, so this removal never executes on the one platform ' +
    'removeTree exists to tolerate a sharing violation on',
  'packages/persistence/test/helpers/keychain.ts::dir':
    'the darwin-only gate returns before the mkdtempSync, so on win32 the tree is never created ' +
    'and the removal never runs; the call is already inside its own try/catch, which says so',
  'plugins/claude-code/test/journey/harness.ts::this.storeDir':
    'SetupJourney.corruptStore() rebuilds a fixture PRECONDITION, not a teardown — swallowing ' +
    'a genuine win32 EPERM here would silently proceed against a stale store instead of ' +
    'failing loud, which is worse than the flake removeTree exists to tolerate elsewhere',
};

describe('bare rmSync teardown of a store- or spawn-touched temp tree', () => {
  it(
    'flags no site outside the documented, reasoned exceptions',
    () => {
      expect(riskySiteKeys()).toEqual(Object.keys(DOCUMENTED_EXCEPTIONS).sort());
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it(
    'every documented exception is a real file, a real still-flagged site, and reasoned',
    () => {
      const tracked = new Set(trackedFiles());
      for (const [key, reason] of Object.entries(DOCUMENTED_EXCEPTIONS)) {
        const sepIndex = key.indexOf('::');
        const file = key.slice(0, sepIndex);
        const ident = key.slice(sepIndex + 2);

        expect(tracked.has(file), `${file} is not a tracked file`).toBe(true);
        expect(reason.length, `${key} has no reason recorded`).toBeGreaterThan(MIN_REASON_CHARS);

        const sites = riskyRemovalsIn(file).map((s) => s.ident);
        expect(sites, `${key} is no longer flagged — the exception can be dropped`).toContain(
          ident,
        );
      }
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it(
    'excludes removeTree/removeTrees’s own implementation, in both the root helper and the ' +
      'package-walled peer copy',
    () => {
      const definitions = [
        'test/helpers/remove-tree.ts',
        'packages/persistence/test/helpers/temp-store.ts',
      ];
      for (const file of definitions) {
        const code = stripComments(read(file));
        // The positive control for this case: the file really does contain the
        // literal shape being excluded, so the assertion below is not vacuous.
        expect(code, `${file} no longer defines removeTree the expected way`).toMatch(
          /\bfunction\s+removeTree\s*\([^)]*\)[\s\S]*?\brmSync\s*\([^,]+,\s*\{[^}]*recursive\s*:\s*true/,
        );
        expect(riskyBareRemovals(code), `${file}'s own removeTree should not self-flag`).toEqual(
          [],
        );
      }
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it('reads the tracked tree, not an empty list', () => {
    const files = candidateFiles();
    expect(files.length).toBeGreaterThan(50);
    expect(files).toContain('packages/persistence/test/helpers/temp-store.ts');
  });

  describe('the detector', () => {
    it('flags a bare removal of a store this same scope opened and closed', () => {
      const source = [
        "describe('x', () => {",
        '  let base;',
        '  let db;',
        '  beforeEach(() => { base = mkdtempSync(x); db = openLocalDatabase(join(base, "data")); });',
        '  afterEach(() => { db.close(); rmSync(base, { recursive: true, force: true }); });',
        '});',
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([{ ident: 'base', pos: expect.any(Number) }]);
    });

    it('does not flag the same shape once it is routed through removeTree', () => {
      const source = [
        "describe('x', () => {",
        '  let base;',
        '  let db;',
        '  beforeEach(() => { base = mkdtempSync(x); db = openLocalDatabase(join(base, "data")); });',
        '  afterEach(() => { db.close(); removeTree(base); });',
        '});',
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([]);
    });

    it('flags a bare removal of a directory a real spawn ran from', () => {
      const source = [
        'const stage = mkdtempSync(x);',
        'try {',
        "  execFileSync('tar', ['-czf', archivePath, '-C', stage, rootName], { stdio: 'pipe' });",
        '} finally {',
        '  rmSync(stage, { recursive: true, force: true });',
        '}',
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([{ ident: 'stage', pos: expect.any(Number) }]);
    });

    it('does not chase an identifier reused by an unrelated, non-enclosing scope', () => {
      // The false-positive trap that motivated scoping to the DECLARATION —
      // a `home` local to one `it()` sharing a name with a `home` parameter
      // that a completely different, non-enclosing function opens a store on.
      const source = [
        'async function inventory(home) {',
        '  const db = openLocalDatabase(dataDir(home));',
        '  db.close();',
        '}',
        "it('x', () => {",
        '  const home = join(dir, "linkhome");',
        '  rmSync(home, { recursive: true });',
        '});',
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([]);
    });

    it('does not flag a single-file, non-recursive removal', () => {
      const source = [
        'const db = openLocalDatabase(dir);',
        'db.close();',
        'rmSync(dir, { force: true });',
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([]);
    });

    it('does not flag rmSync inside a function literally named removeTree', () => {
      const source = [
        'function removeTree(dir) {',
        '  const db = openLocalDatabase(dir);',
        '  rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });',
        '}',
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([]);
    });

    it('is not fooled by a store call mentioned only in a comment', () => {
      const source = [
        '// openLocalDatabase(base) used to be called directly here.',
        'rmSync(base, { recursive: true, force: true });',
      ].join('\n');
      expect(riskyBareRemovals(stripComments(source))).toEqual([]);
    });

    it('excludes product code: isTestFile rejects a plain src/ path', () => {
      expect(isTestFile('packages/persistence/src/file-lock.ts')).toBe(false);
      expect(isTestFile('packages/persistence/test/helpers/temp-store.ts')).toBe(true);
      expect(isTestFile('cli/test/commands/init.test.ts')).toBe(true);
    });

    it('flags a bare removal of a tree a spawn was handed a path INSIDE', () => {
      const source = [
        'let dir;',
        'let homeDir;',
        "beforeEach(() => { dir = mkdtempSync(x); homeDir = join(dir, 'home'); });",
        "it('x', () => { spawnSync(node, [script], { env: { HOME: homeDir } }); });",
        'afterEach(() => { rmSync(dir, { recursive: true, force: true }); });',
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([{ ident: 'dir', pos: expect.any(Number) }]);
    });

    it('does not walk UPWARD, from the removed tree to the parent a spawn holds', () => {
      // A child whose cwd is the PARENT holds nothing inside `homeDir`, and
      // reaching for it would re-open the unrelated-sibling false positive the
      // argument-list rule exists to close.
      const source = [
        'let dir;',
        'let homeDir;',
        "beforeEach(() => { dir = mkdtempSync(x); homeDir = join(dir, 'home'); });",
        "it('x', () => { spawnSync(node, [script], { cwd: dir }); });",
        'afterEach(() => { rmSync(homeDir, { recursive: true, force: true }); });',
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([]);
    });

    it('correlates a for-of removal on the LIST, not on the loop binding', () => {
      // The binding IS its own nearest-preceding declaration, so scoping to it
      // collapses the window to the teardown hook's own body and correlates
      // against nothing at all.
      const source = [
        'const dirs = [];',
        'function tempStoreDir() { const dir = mkdtempSync(x); dirs.push(dir); return dir; }',
        "it('x', () => { const db = openLocalDatabase(join(tempStoreDir(), 'data')); db.close(); });",
        'afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });',
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([{ ident: 'dirs', pos: expect.any(Number) }]);
    });

    it('sees a removal whose argument DRAINS the list rather than naming it', () => {
      // `dirs.pop()` is a call expression, so a call regex matching identifiers
      // alone never considers this site at all.
      const source = [
        'const dirs = [];',
        'const tempDir = () => { const dir = mkdtempSync(x); dirs.push(dir); return dir; };',
        "it('x', () => { const binDir = tempDir(); execFileSync(cmd, [], { cwd: binDir }); });",
        "afterEach(() => { while (dirs.length > 0) rmSync(dirs.pop() ?? '', { recursive: true, force: true }); });",
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([{ ident: 'dirs', pos: expect.any(Number) }]);
    });

    it('holds a drained removal to the same recursive-only bar as a named one', () => {
      const source = [
        'const dirs = [];',
        'const tempDir = () => { const dir = mkdtempSync(x); dirs.push(dir); return dir; };',
        "it('x', () => { const binDir = tempDir(); execFileSync(cmd, [], { cwd: binDir }); });",
        "afterEach(() => { while (dirs.length > 0) rmSync(dirs.pop() ?? '', { force: true }); });",
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([]);
    });

    it('flags a spawn a test helper performs on the caller’s behalf', () => {
      const source = [
        'let base;',
        'beforeEach(() => { base = mkdtempSync(x); });',
        "it('x', async () => { await runConcurrentSettingsWriters(base, jobs); });",
        'afterEach(() => { rmSync(base, { recursive: true, force: true }); });',
      ].join('\n');
      expect(riskyBareRemovals(source, new Set(['runConcurrentSettingsWriters']))).toEqual([
        { ident: 'base', pos: expect.any(Number) },
      ]);
    });

    it('treats an ordinary call as a spawn only because the helper set says so', () => {
      // The control for the case above: the same source, with nothing declared
      // to spawn, must stay clear — or every call taking a temp dir would read
      // as a spawn of it.
      const source = [
        'let base;',
        'beforeEach(() => { base = mkdtempSync(x); });',
        "it('x', async () => { await runConcurrentSettingsWriters(base, jobs); });",
        'afterEach(() => { rmSync(base, { recursive: true, force: true }); });',
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([]);
    });

    it('reads a spawning TEST helper into that set, and never a product module', () => {
      // Real files, because the restriction to test helpers is what keeps this
      // from flagging every caller of any src/ function that spawns somewhere.
      const race = 'packages/persistence/test/concurrency/settings-race.test.ts';
      const raceCode = stripComments(read(race));
      expect([...spawningTestHelperImports(race, raceCode)]).toContain(
        'runConcurrentSettingsWriters',
      );

      // extension.test.ts imports from cli/src/commands/extension.ts, which
      // spawns `reg` — and must still contribute nothing, because that is
      // product code.
      const ext = 'cli/test/commands/extension.test.ts';
      expect([...spawningTestHelperImports(ext, stripComments(read(ext)))]).toEqual([]);
    });

    it('flags a list removal in a scope that releases a memoised store', () => {
      // A page render opens the store under a redirected home through the app's
      // own module, so the file never names openLocalDatabase; the release is
      // the only trace of it.
      const source = [
        'export function tempHomes(prefix) {',
        '  const made = [];',
        '  afterAll(async () => {',
        '    await releaseLocalStore();',
        '    for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true });',
        '  });',
        '  return () => { const dir = mkdtempSync(prefix); made.push(dir); return dir; };',
        '}',
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([{ ident: 'made', pos: expect.any(Number) }]);
    });

    it('does not read a release in an unrelated, non-enclosing scope as touching the tree', () => {
      const source = [
        'function reset() { closeStore(); }',
        "it('x', () => {",
        '  const scratch = mkdtempSync(x);',
        '  rmSync(scratch, { recursive: true, force: true });',
        '});',
      ].join('\n');
      expect(riskyBareRemovals(source)).toEqual([]);
    });
  });
});
