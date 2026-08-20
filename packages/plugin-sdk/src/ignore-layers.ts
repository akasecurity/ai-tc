// Layered gitignore evaluation, shared by every tree walk in this repository:
// the SessionStart project inventory (./project-files.ts), the dashboard's
// folder scan (@akasecurity/local-ops fs-scan) and the standalone worktree
// scanner (@akasecurity/scanner walk). All three accumulate one matcher per
// ignore file down the tree and ask the same question of every entry, so the
// representation lives once rather than three times — three copies of this
// drift, and the two that were copies carried an O(entries x layers) form long
// after the third stopped.
//
// THE REPRESENTATION IS THE POINT. The obvious shape is a per-layer BASE
// directory plus a `relative(base, absPath)` per layer per entry, which is a
// path diff — allocation, separator normalisation, and no way to stop early.
// Instead the walk carries ONE repo-relative posix path per directory (`dirRel`)
// and every layer keeps an integer OFFSET into it, so addressing an entry the
// way a given layer's own ignore file addresses it is a slice of a string the
// walk already built. Holding a per-layer prefix instead would rebuild all of
// them on every descent — O(depth) strings of O(depth) characters per directory,
// for prefixes the deepest-first lookup usually never reads.
//
// AND THE ORDER IS THE OTHER HALF. Git resolves deepest-wins: a deeper ignore
// file's verdict — ignore OR `!` re-include — overrides a shallower one's. A
// shallow-to-deep loop that overwrites a running verdict reaches the same answer
// only by consulting EVERY layer, while walking from the deepest and returning
// at the first layer with an opinion reaches it without touching the ancestors
// behind it. A layer matching neither is silent and the search continues past
// it, which is why the tri-state below cannot collapse to a boolean:
// `unignored` is an explicit re-include that overrides a caller's own default
// skip floor, and `unmatched` is no opinion at all.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import ignore, { type Ignore } from 'ignore';

/**
 * One ignore file's rules, plus how much of the walk's current directory path
 * belongs to the directory that contains it — git patterns are relative to
 * their own ignore file, not to the walk root.
 */
export interface IgnoreLayer {
  matcher: Ignore;
  /** Length of `dirRel` at the directory holding this ignore file. */
  anchorLen: number;
}

/**
 * What the layer stack says about one entry.
 *
 * `unignored` is deliberately distinct from `unmatched`: an explicit `!`
 * re-include is a verdict, and callers that keep a default skip floor
 * (`node_modules`, dot-directories) let it override that floor, which "no layer
 * matched" must not do.
 */
export type IgnoreState = 'ignored' | 'unignored' | 'unmatched';

/**
 * Read `dir`'s `filename` into a matcher anchored at `anchorLen`.
 *
 * Fail-open: an unreadable or malformed file yields no layer. Every caller here
 * treats a missing layer as "no opinion", so an unreadable ignore file scans or
 * inventories MORE, never less.
 */
export function readIgnoreLayer(
  dir: string,
  filename: string,
  anchorLen: number,
): IgnoreLayer | undefined {
  try {
    return { matcher: ignore().add(readFileSync(join(dir, filename), 'utf8')), anchorLen };
  } catch {
    return undefined;
  }
}

/**
 * `name` as the layer anchored at `anchorLen` addresses it: posix,
 * anchor-relative.
 *
 * PRECONDITION: the anchor is an ANCESTOR of `dirRel` — which every walk here
 * guarantees, since a layer is only ever accumulated on the way down and every
 * descent appends to `dirRel`. It is an offset arithmetic, not a path
 * comparison, so a stack carrying a layer from somewhere else produces a string
 * with a leading `/` and the `ignore` package rejects that outright rather than
 * matching it.
 */
export function relToAnchor(dirRel: string, anchorLen: number, name: string): string {
  if (anchorLen === dirRel.length) return name;
  // Skip the separator that follows the anchor, unless the anchor is the root
  // and contributes no leading segment at all.
  return `${dirRel.slice(anchorLen === 0 ? 0 : anchorLen + 1)}/${name}`;
}

/**
 * The layered verdict for the entry named `name` in the directory `dirRel`
 * addresses — the DEEPEST layer with an opinion, reached without consulting the
 * ancestors behind it.
 *
 * Directories are tested with a trailing slash so `dir/`-style patterns match.
 */
export function evaluateIgnore(
  layers: readonly IgnoreLayer[],
  dirRel: string,
  name: string,
  isDir: boolean,
): IgnoreState {
  const suffix = isDir ? '/' : '';
  for (let i = layers.length - 1; i >= 0; i--) {
    const layer = layers[i];
    if (layer === undefined) continue;
    const verdict = layer.matcher.test(relToAnchor(dirRel, layer.anchorLen, name) + suffix);
    if (verdict.ignored) return 'ignored';
    if (verdict.unignored) return 'unignored';
  }
  return 'unmatched';
}

/**
 * The walk-relative posix path of `name` inside the directory `dirRel`
 * addresses. Built by appending one component per descent rather than diffed
 * against the root — which is also what makes an `anchorLen` a stable offset
 * for the whole subtree below the layer that set it.
 */
export function childRel(dirRel: string, name: string): string {
  return dirRel === '' ? name : `${dirRel}/${name}`;
}

/**
 * A layer stack with `layer` appended, or the same array when there is nothing
 * to add.
 *
 * Copying only where a directory CONTRIBUTES a layer is what keeps the descent
 * free on the overwhelmingly common tree that carries one `.gitignore` at its
 * root: an anchor offset never moves, so the same array can descend unchanged.
 */
export function withLayer(
  layers: readonly IgnoreLayer[],
  layer: IgnoreLayer | undefined,
): readonly IgnoreLayer[] {
  return layer ? [...layers, layer] : layers;
}
