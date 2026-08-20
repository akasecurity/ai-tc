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
 * What counts as the pattern, precisely: a tracked test file's own `rmSync(x,
 * { recursive: true, … })` call, where `x` is the same identifier a
 * `openLocalDatabase(…)` or a real spawn (`execFileSync`/`spawnSync`/`spawn`)
 * was given somewhere in `x`'s own declaration scope — the block `x` was
 * declared in, walked from that block's start to its end, not merely up to the
 * removal (a `beforeEach` opens the store; a sibling `afterEach` removes it,
 * and the open can sit either side of the removal in the file's own text). A
 * `let`/`const`/`var` declaration is looked for; a bare property access
 * (`this.storeDir`) or an identifier this file never sees declared is treated
 * as scoped to the whole file, which is the safe direction to be wrong in —
 * it can over-match and read a real exception's site correctly, never quietly
 * clear a real one.
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
 * real). Nothing here relies on that being wrong in a direction that hides a
 * real site — `DOCUMENTED_EXCEPTIONS` is an exact set checked against what the
 * tree actually holds, so a detector regression that stops seeing a real risky
 * site fails on the exact-set count either way.
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
  const escaped = ident.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const declRe = new RegExp(`\\b(?:let|const|var)\\s+${escaped}\\b`, 'g');
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

/** Whether `pos` sits directly inside a function named `removeTree`/`removeTrees`. */
function isRemoveTreeDefinition(code, pos) {
  const blockStart = enclosingBlockStart(code, pos);
  const preface = code.slice(Math.max(0, blockStart - 200), blockStart);
  return /\bfunction\s+removeTrees?\s*\(/.test(preface);
}

/**
 * Every `rmSync(ident, { recursive: true, … })` call in `code` whose `ident`
 * is, within its own declaration scope, also handed to `openLocalDatabase(…)`
 * or used as an argument to a real spawn (`execFileSync`/`spawnSync`/`spawn`)
 * — the two out-of-process actors a bare removal can race. Excludes a call
 * sitting inside `removeTree`/`removeTrees`'s own body.
 * @param {string} code comments already stripped
 * @returns {{ ident: string, pos: number }[]}
 */
function riskyBareRemovals(code) {
  const found = [];
  const callRe =
    /\brmSync\s*\(\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*,\s*\{([^}]*)\}\s*\)/g;
  let m;
  while ((m = callRe.exec(code))) {
    const [, ident, opts] = m;
    if (!/recursive\s*:\s*true/.test(opts)) continue;
    const pos = m.index;
    if (isRemoveTreeDefinition(code, pos)) continue;

    const [scopeStart, scopeEnd] = declarationScope(code, ident, pos);
    const window = code.slice(scopeStart, scopeEnd);
    const escaped = ident.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    const hasStoreOpen = new RegExp(`\\bopenLocalDatabase\\s*\\([^)]*\\b${escaped}\\b`).test(
      window,
    );

    // A real spawn correlates only when `ident` appears inside that CALL's own
    // argument list (its cwd, its env, an argv entry) — not merely somewhere
    // else in the same scope, which is what let `home` in one unrelated `it()`
    // read as spawn-touched because a distant sibling `it()` also spawned
    // something. `[\s\S]{0,400}` bounds the argument-list window; every real
    // call site here fits well inside it.
    const spawnArgsRe = /\b(?:execFileSync|spawnSync|spawn)\s*\(([\s\S]{0,400}?)\)/g;
    let hasSpawn = false;
    let sm;
    while ((sm = spawnArgsRe.exec(window))) {
      if (new RegExp(`\\b${escaped}\\b`).test(sm[1])) {
        hasSpawn = true;
        break;
      }
    }

    if (hasStoreOpen || hasSpawn) found.push({ ident, pos });
  }
  return found;
}

// Memoized for the module's life — nothing here mutates the tree mid-run, and
// several `it()`s below ask the same question of the same files.
let candidateFilesCache;
const readCache = new Map();

/** Every tracked `.ts`/`.tsx` file this workspace treats as test code. */
function candidateFiles() {
  candidateFilesCache ??= trackedFiles()
    .filter((f) => /\.tsx?$/.test(f))
    .filter(isTestFile)
    .sort();
  return candidateFilesCache;
}

function read(file) {
  let source = readCache.get(file);
  if (source === undefined) {
    source = readFileSync(join(REPO_ROOT, ...file.split('/')), 'utf8');
    readCache.set(file, source);
  }
  return source;
}

/** `"<file>::<ident>"` for every risky bare removal the tree currently holds. */
function riskySiteKeys() {
  const keys = [];
  for (const file of candidateFiles()) {
    for (const { ident } of riskyBareRemovals(stripComments(read(file)))) {
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

        const sites = riskyBareRemovals(stripComments(read(file))).map((s) => s.ident);
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
  });
});
