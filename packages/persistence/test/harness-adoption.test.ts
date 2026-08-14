/**
 * The store harness is adopted, and stays adopted.
 *
 * `helpers/temp-store.ts` absorbs three defects that were each found the hard
 * way — a double `close()` (`node:sqlite` throws on the second), a tree Windows
 * will not delete while a handle is open, and a mode restore that has to run
 * before the removal. None of those is visible at a call site: a hand-rolled
 * store passes on POSIX, and the leak it left surfaces as the NEXT suite's
 * teardown failing on the Windows leg. So this is enforced from the tree rather
 * than left to review, which is where it went unnoticed for as long as it did.
 *
 * The file set is derived from `git ls-files`, never listed here — a suite added
 * tomorrow is covered without an edit, which is the whole point. Exactly one
 * file is held out of it, this one, for the reason recorded at `SELF` below; the
 * hole that opens is bounded by a case of its own rather than by trust.
 *
 * Comments are stripped before anything is matched, and that is not tidiness. A
 * plain grep over this directory counts prose as a call: `paths.test.ts` and
 * `local-layout.test.ts` both name `openLocalDatabase` in a comment and open no
 * store at all, so a grep-shaped detector reports them as hand-rolling for ever
 * and the only way to "fix" it is to edit a comment.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * This file, as `git ls-files` reports it — held out of the walk below.
 *
 * The detector strips comments but not STRING LITERALS, and this suite's own
 * controls are literals holding the very tokens it searches for: a control that
 * did not look like real code would not be a control. So this is the one file
 * the detector cannot be pointed at — it reports itself as both hand-rolling a
 * tree and opening a store, and no edit short of disfiguring the controls
 * changes that.
 *
 * This went unnoticed until the file was COMMITTED, because `git ls-files` reads
 * the index: while it was untracked the walk never returned it and the suite ran
 * green. A guard that reads the tree has to be re-run once it is part of the
 * tree.
 *
 * Derived rather than written out, so a rename carries the exclusion with it
 * instead of stranding it on a name no file has. `split(sep).join('/')` is the
 * inverse of `toNative` — git prints posix paths on every platform.
 */
const SELF = relative(PACKAGE_ROOT, fileURLToPath(import.meta.url))
  .split(sep)
  .join('/');

// A floor on the recorded reasons below, not a quality bar — length cannot tell
// a real justification from a long placeholder. It is here only to stop an entry
// landing with `''` or `'n/a'`, which would read as reviewed and say nothing. The
// shortest genuine reason in either map today is comfortably over it.
const MIN_REASON_CHARS = 20;

/**
 * Source with comments removed, so a mention in prose is never read as a call.
 *
 * A peer copy of `packages/eslint-config/test/effective-config.test.js`'s
 * stripper — a package wall blocks the import, and CLAUDE.md's rule for that is
 * to copy it rather than reinvent it, which means copying the form that gets the
 * hard case right. The `[^:]` is that case: a bare `\/\/.*$` truncates at the
 * `//` in `'https://…'` and takes the rest of the LINE with it, so a real
 * `openLocalDatabase(dir)` after a URL literal goes unseen — and this guard's one
 * job is to notice exactly that. Seven files in this directory carry a `://`.
 *
 * Block comments go first, because a `//` inside one would otherwise survive as
 * code once the block markers were gone.
 *
 * KNOWN LIMIT, pinned as a case below rather than left to be rediscovered:
 * neither pass tokenizes strings, so a block-comment OPEN marker inside a string
 * literal, paired with a later CLOSE marker, still collapses everything between
 * them. Closing that needs a real tokenizer; what stops it mattering is that the
 * whole-set assertions here are exact, so a file that vanished from the
 * detector's view fails the count rather than passing quietly.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/** Whether `source` builds its own temp tree, or opens a store, in CODE. */
function storeSetup(source: string): { mkdtemp: boolean; open: boolean } {
  const code = stripComments(source);
  return {
    mkdtemp: /\bmkdtempSync\s*\(/.test(code),
    open: /\bopenLocalDatabase\s*\(/.test(code),
  };
}

/** git reports posix paths on every platform; `join` yields native ones. */
const toNative = (p: string): string => p.split('/').join(sep);

/** Every tracked test file, this one included. */
function allTrackedTestFiles(): string[] {
  const out = execFileSync('git', ['ls-files', 'test'], {
    cwd: PACKAGE_ROOT,
    encoding: 'utf8',
  });
  return (
    out
      .split('\n')
      // Trimmed before the suffix test, not after: a line arriving as
      // `…/x.test.ts\r` fails `endsWith` and drops out, and if every line did the
      // set would come back EMPTY — which satisfies the two exact-set assertions
      // below by having nothing to compare. The `length > 50` control is what
      // would catch that, and it should never have to.
      .map((p) => p.trim())
      .filter((p) => p.endsWith('.test.ts'))
      .sort()
  );
}

/** The suites the adoption rules apply to — every tracked one but this. */
function trackedTestFiles(): string[] {
  return allTrackedTestFiles().filter((p) => p !== SELF);
}

function read(relativePath: string): string {
  return readFileSync(join(PACKAGE_ROOT, toNative(relativePath)), 'utf8');
}

/**
 * Every test file that builds its own temp tree, with the reason it is not the
 * harness's to build.
 *
 * Pinned as an EXACT set rather than a floor. A floor forbids only removals, so
 * a suite that starts hand-rolling tomorrow would slip in under it — and the
 * whole failure mode here is a new file quietly re-deriving a teardown, not an
 * old one losing its harness.
 *
 * Nothing in this map may open a store: that is the separate, exception-free
 * assertion below, and these entries exist because they need a bare directory,
 * a child process's own home, or a tree shaped in a way the harness's fixed
 * `settings/` + `data/` layout would pre-empt.
 */
const OWN_TEMP_TREE: Readonly<Record<string, string>> = {
  'test/concurrency/fingerprint-race.test.ts':
    'the home is handed to child processes, which mint into it before any handle here exists',
  'test/concurrency/settings-race.test.ts':
    'the home is handed to child processes racing settings.json, and holds no store',
  'test/file-lock.test.ts': 'a bare directory to take sibling .lock files in — no store',
  'test/fingerprint.test.ts':
    'on the harness for its store; the extra tree is a second home used to pin key isolation',
  'test/helpers/settings-writers.test.ts':
    'drives the settings child-process writers over a plain home — no store',
  'test/internal/snapshot.test.ts':
    'builds bare DatabaseSync files to snapshot, with no ~/.aka layout around them',
  'test/paths-link-fallback.test.ts':
    'the subject is the symlink fallback in the path helpers themselves — no store',
  'test/settings.test.ts': 'settings.json only; the layout the harness creates is not wanted here',
  'test/vault/key-provider.test.ts':
    'key files under a bare directory, ahead of any store that would hold them',
};

/**
 * Suites whose raw connections must stay hand-held, and what breaks if they do
 * not. `store.openRaw()` keeps every handle open until teardown, so it is the
 * wrong tool wherever the CLOSE is part of the setup.
 *
 * Named one file at a time rather than sniffed for, because "a raw handle on the
 * harness's own store file" is not a thing a regex can tell from a raw handle on
 * a `:memory:` database or a bare fixture file — several suites here open both.
 *
 * So this is a FLOOR, and deliberately unlike `OWN_TEMP_TREE`'s exact set. Do not
 * "fix" the asymmetry: an exact set needs a DERIVED set to compare against, and
 * the paragraph above is the reason no such set can be derived here. Pinning one
 * anyway would mean hand-writing both sides and asserting a list against itself.
 * What the floor still buys is that removing an entry is a visible act.
 */
const RAW_BY_HAND: Readonly<Record<string, string>> = {
  'test/repositories/legacy-writers.test.ts':
    'it replays a legacy PROCESS — one connection, one statement, closed again, never overlapping another — which is the sequence under test',
};

describe('store harness adoption', () => {
  it('no suite that opens a store also builds its own temp tree', () => {
    // The issue's own predicate, and it carries no exceptions: a file reaching
    // `openLocalDatabase` has a store to leak, and the harness is what closes
    // it on the path where an assertion threw first.
    const handRolled = trackedTestFiles().filter((file) => {
      const { mkdtemp, open } = storeSetup(read(file));
      return mkdtemp && open;
    });
    expect(handRolled).toEqual([]);
  });

  it('pins exactly which suites build a temp tree of their own', () => {
    const own = trackedTestFiles().filter((file) => storeSetup(read(file)).mkdtemp);
    expect(own).toEqual(Object.keys(OWN_TEMP_TREE).sort());
  });

  it('every pinned exception is a real file that really does build one', () => {
    // Otherwise an entry outlives the suite it described, and the exact-set
    // assertion above starts being satisfied by a stale name.
    const tracked = new Set(trackedTestFiles());
    for (const [file, reason] of Object.entries(OWN_TEMP_TREE)) {
      expect(tracked.has(file), `${file} is not a tracked test file`).toBe(true);
      expect(storeSetup(read(file)).mkdtemp, `${file} no longer builds its own tree`).toBe(true);
      expect(reason.length, `${file} has no reason recorded`).toBeGreaterThan(MIN_REASON_CHARS);
    }
  });

  it('keeps the deliberately hand-held raw connections hand-held', () => {
    // This is the AC that reads as "change nothing", and a preservation rule that
    // nothing checks is one a mechanical sweep undoes on its next pass. The reason
    // each entry carries is the thing to read before converting it — and deleting
    // the entry is then a visible act rather than a silent one.
    //
    // It reads the file with comments STRIPPED, so the note at the top of the
    // subject explaining why it does not use openRaw() is not mistaken for a call.
    const tracked = new Set(trackedTestFiles());
    for (const [file, reason] of Object.entries(RAW_BY_HAND)) {
      // Held to the same two checks as `OWN_TEMP_TREE`'s entries. The maps read
      // as symmetric and were not: `reason` reached only an assertion MESSAGE
      // here, so an entry could land with `''` and pass — and a name that no
      // longer exists surfaced as a bare ENOENT out of `read` rather than saying
      // which map it came from. Being a floor is the deliberate asymmetry (see
      // the note on the map); an unreviewed entry was not.
      expect(tracked.has(file), `${file} is not a tracked test file`).toBe(true);
      expect(reason.length, `${file} has no reason recorded`).toBeGreaterThan(MIN_REASON_CHARS);

      const code = stripComments(read(file));
      expect(code, `${file}: ${reason}`).not.toContain('store.openRaw(');
      expect(code, `${file} no longer opens a raw connection at all`).toContain(
        'new DatabaseSync(',
      );
    }
  });

  // The controls. Without them every assertion above is satisfied by a detector
  // that matches nothing, and the suite would report full adoption at any state
  // of the tree at all.
  describe('the detector', () => {
    it('sees a hand-rolled store', () => {
      const source = [
        "import { mkdtempSync, rmSync } from 'node:fs';",
        "import { openLocalDatabase } from '../src/database.ts';",
        "const dir = mkdtempSync(join(tmpdir(), 'aka-x-'));",
        'const db = openLocalDatabase(dir);',
      ].join('\n');
      expect(storeSetup(source)).toEqual({ mkdtemp: true, open: true });
    });

    it('does not see either one in a line comment', () => {
      const source = [
        '// openLocalDatabase(dataDir(home)) creates ~/.aka itself as a parent',
        '// and the older suites did this with mkdtempSync(join(tmpdir(), ...)).',
        "import { useTempStore } from './helpers/temp-store.ts';",
      ].join('\n');
      expect(storeSetup(source)).toEqual({ mkdtemp: false, open: false });
    });

    it('does not see either one in a block comment', () => {
      const source = [
        '/**',
        ' * A hook whose openLocalDatabase(x) throws writes nothing and exits 0.',
        ' * // mkdtempSync(y) is how this used to be written.',
        ' */',
        "import { useTempStore } from './helpers/temp-store.ts';",
      ].join('\n');
      expect(storeSetup(source)).toEqual({ mkdtemp: false, open: false });
    });

    it('holds out itself and nothing else, and really does open no store', () => {
      // The exclusion is the one hole in an otherwise exception-free walk, so it
      // is checked twice.

      // It is exactly one file. A second name added to the filter would take a
      // real suite out of the exact-set assertions above without failing
      // anything — the set would simply be smaller and still match a map that
      // had shrunk to meet it.
      const held = allTrackedTestFiles().filter((p) => !trackedTestFiles().includes(p));
      expect(held).toEqual([SELF]);

      // And the held-out file is checked by the one means the detector cannot
      // be: its IMPORTS. A suite that genuinely opened a store would have to
      // import `openLocalDatabase`, and one that built its own tree would have
      // to import `mkdtempSync` — neither of which a string literal can supply.
      // So the exclusion cannot quietly cover a real regression in this file.
      const imports = stripComments(read(SELF))
        .split('\n')
        .filter((line) => line.startsWith('import '))
        .join('\n');
      expect(imports).not.toContain('openLocalDatabase');
      expect(imports).not.toContain('mkdtempSync');
    });

    it('still sees a call sharing a line with a URL literal', () => {
      // The `://` case the `[^:]` guard exists for. A bare `\/\/.*$` strips from
      // the URL's own slashes and takes the call after it, so this returns
      // `open: false` and the file reads as fully migrated while it is not.
      const source =
        "db.sourceProject.upsert({ url: 'https://github.com/org/x.git' }); const db2 = openLocalDatabase(dir);";
      expect(storeSetup(source)).toEqual({ mkdtemp: false, open: true });
    });

    it('is documented-blind to a block-comment marker inside a string', () => {
      // The known limit, pinned so it stays known. Closing it needs a tokenizer;
      // what this case buys is that nobody rediscovers it as a mystery.
      const source = "const a = '/*'; const db = openLocalDatabase(dir); const b = '*/';";
      expect(storeSetup(source)).toEqual({ mkdtemp: false, open: false });
    });

    it('still sees a call on a line that ends in a comment', () => {
      // The pairing that makes the two rules above safe: stripping a trailing
      // comment must not take the code in front of it.
      const source = 'const db = openLocalDatabase(dir); // NOTE: no sample fixtures';
      expect(storeSetup(source)).toEqual({ mkdtemp: false, open: true });
    });

    it('reads the tracked tree, not an empty list', () => {
      // A `git ls-files` that returned nothing would satisfy all three
      // assertions above, and this suite would go green having read no file.
      const files = trackedTestFiles();
      expect(files.length).toBeGreaterThan(50);
      expect(files).toContain('test/repositories/findings.test.ts');
    });
  });
});
