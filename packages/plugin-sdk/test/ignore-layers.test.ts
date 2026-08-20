import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  childRel,
  evaluateIgnore,
  type IgnoreLayer,
  readIgnoreLayer,
  relToAnchor,
  withLayer,
} from '../src/ignore-layers.ts';

// The layered ignore evaluation shared by all three tree walkers.
//
// It is unit-tested here rather than only through the walkers because the case
// that decides its arithmetic is the one none of them happened to build: a
// `.gitignore` anchored PART WAY down the tree, evaluated against an entry
// deeper still. A layer in the directory being walked takes an early return, and
// a layer at the root slices from zero — so both of those stay correct however
// the offset is computed, and every walker suite in this repository passed with
// the anchor arithmetic deliberately broken until these cases existed.

let home: string | undefined;

afterEach(() => {
  if (home) rmSync(home, { recursive: true, force: true });
  home = undefined;
});

/** A directory holding `.gitignore` with `content`, plus the layer that reads it. */
function layerAt(anchorLen: number, content: string): IgnoreLayer {
  home ??= mkdtempSync(join(tmpdir(), 'aka-layers-'));
  const dir = mkdtempSync(join(home, 'd-'));
  writeFileSync(join(dir, '.gitignore'), content);
  const layer = readIgnoreLayer(dir, '.gitignore', anchorLen);
  if (!layer) throw new Error('the fixture layer was not read');
  return layer;
}

describe('relToAnchor addresses an entry the way its own ignore file does', () => {
  it('a layer in the directory being walked sees the bare name', () => {
    expect(relToAnchor('src/gen', 'src/gen'.length, 'a.ts')).toBe('a.ts');
  });

  it('a layer at the walk root sees the whole walk-relative path', () => {
    // anchorLen 0 contributes no leading segment, so nothing is skipped — the
    // branch that reads `anchorLen === 0 ? 0 : anchorLen + 1` exists for this.
    expect(relToAnchor('src/gen', 0, 'a.ts')).toBe('src/gen/a.ts');
  });

  it('a layer PART WAY down sees the path relative to its own directory', () => {
    // THE case. The `+ 1` skips the separator that follows the anchor; without
    // it the layer is handed `/gen/a.ts`, which is an absolute path to the
    // matcher and matches none of its patterns. Both cases above are blind to
    // it — one returns early, the other slices from zero.
    expect(relToAnchor('src/gen', 'src'.length, 'a.ts')).toBe('gen/a.ts');
  });
});

describe('the layered verdict is the deepest layer with an opinion', () => {
  it('a mid-tree layer ignores an entry in a directory below it', () => {
    const layers = [layerAt(0, 'node_modules/\n'), layerAt('src'.length, 'gen/\n*.snap\n')];

    // Anchored at `src`, addressed from `src/gen` — the arithmetic case above,
    // reached the way a walker reaches it.
    expect(evaluateIgnore(layers, 'src/gen', 'a.snap', false)).toBe('ignored');
    expect(evaluateIgnore(layers, 'src', 'gen', true)).toBe('ignored');
    // The control: the same layer stack has no opinion about an ordinary file
    // in a sibling directory, so the assertions above are about the patterns
    // and not about a matcher that says `ignored` to everything. (`src/gen`
    // itself would not do — a gitignore `gen/` covers everything under it.)
    expect(evaluateIgnore(layers, 'src/lib', 'a.ts', false)).toBe('unmatched');
  });

  it('a deeper re-include overrides a shallower ignore', () => {
    const root = layerAt(0, '*.log\n');
    const layers = [root, layerAt('src'.length, '!keep.log\n')];

    expect(evaluateIgnore(layers, 'src', 'keep.log', false)).toBe('unignored');
    // Outside `src` the walk never accumulated that layer, so only the shallow
    // rule applies and it stands. Stated as the stack a walk really builds
    // there, not as the same stack asked about another directory: every layer's
    // anchor is an ANCESTOR of the path being addressed, which is the
    // precondition the offset arithmetic is written against.
    expect(evaluateIgnore([root], 'docs', 'keep.log', false)).toBe('ignored');
  });

  it('separates no opinion from an explicit re-include', () => {
    // `unmatched` and `unignored` are both "not ignored" and are NOT
    // interchangeable: a caller with a default skip floor (node_modules,
    // dot-directories) lets an explicit `!` override that floor, which "no layer
    // matched" must never do.
    const layers = [layerAt(0, '!vendor/\n')];
    expect(evaluateIgnore(layers, '', 'vendor', true)).toBe('unignored');
    expect(evaluateIgnore(layers, '', 'src', true)).toBe('unmatched');
  });

  it('tests a directory with a trailing slash so `dir/` patterns match', () => {
    const layers = [layerAt(0, 'build/\n')];
    expect(evaluateIgnore(layers, '', 'build', true)).toBe('ignored');
    // A FILE named `build` is not what `build/` names.
    expect(evaluateIgnore(layers, '', 'build', false)).toBe('unmatched');
  });

  it('an empty stack has no opinion', () => {
    expect(evaluateIgnore([], 'src', 'a.ts', false)).toBe('unmatched');
  });
});

describe('the pieces a walk threads through', () => {
  it('readIgnoreLayer fails open on a file it cannot read', () => {
    home ??= mkdtempSync(join(tmpdir(), 'aka-layers-'));
    const empty = join(home, 'no-ignore-file');
    mkdirSync(empty, { recursive: true });
    // No layer rather than a throw: every caller reads a missing layer as "no
    // opinion", so an unreadable ignore file scans or inventories MORE.
    expect(readIgnoreLayer(empty, '.gitignore', 0)).toBeUndefined();
  });

  it('childRel appends one component per descent', () => {
    expect(childRel('', 'src')).toBe('src');
    expect(childRel('src', 'gen')).toBe('src/gen');
  });

  it('withLayer returns the SAME array when a directory contributes nothing', () => {
    // Load-bearing rather than cosmetic: this is what keeps the descent free on
    // the overwhelmingly common tree that carries one `.gitignore` at its root.
    const layers: IgnoreLayer[] = [layerAt(0, '*.log\n')];
    expect(withLayer(layers, undefined)).toBe(layers);

    const grown = withLayer(layers, layerAt(3, '*.tmp\n'));
    expect(grown).not.toBe(layers);
    expect(grown).toHaveLength(2);
    expect(layers).toHaveLength(1);
  });
});
