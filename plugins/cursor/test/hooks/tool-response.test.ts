/**
 * The bounded walk over a structured value. A value past any bound is
 * reported as truncated, never read as clean; each case below pairs a value
 * just inside a bound with one just past it.
 */
import { describe, expect, it } from 'vitest';

import {
  RESULT_WALK_MAX_DEPTH,
  RESULT_WALK_MAX_LEAF_CHARS,
  RESULT_WALK_MAX_LEAVES,
  RESULT_WALK_MAX_TOTAL_CHARS,
  scannableFields,
} from '../../src/hooks/tool-response.ts';

/** A string leaf nested `depth` objects below the root. */
function nested(depth: number, leaf: unknown = 'x'): unknown {
  let node = leaf;
  for (let i = 0; i < depth; i += 1) node = { k: node };
  return node;
}

describe('the walk bounds', () => {
  // Pinned as literals: every case below derives its fixtures from these
  // constants, so without this a raised bound would keep the file green.
  it('are the values this adapter is measured against', () => {
    expect(RESULT_WALK_MAX_DEPTH).toBe(6);
    expect(RESULT_WALK_MAX_LEAVES).toBe(2_000);
    expect(RESULT_WALK_MAX_LEAF_CHARS).toBe(1_000_000);
    expect(RESULT_WALK_MAX_TOTAL_CHARS).toBe(5_000_000);
  });
});

describe('scannableFields', () => {
  it('reads a bare string whole, and an empty one as nothing', () => {
    expect(scannableFields('text')).toEqual({
      fields: [{ path: [], text: 'text' }],
      truncated: false,
    });
    expect(scannableFields('')).toEqual({ fields: [], truncated: false });
  });

  it('reads nothing from a value that holds no text', () => {
    for (const value of [undefined, null, 42, true, {}, []]) {
      expect(scannableFields(value)).toEqual({ fields: [], truncated: false });
    }
  });

  it('collects string leaves with their paths, array indices as strings', () => {
    expect(scannableFields({ a: 'one', b: ['two', 3, { c: 'three' }] })).toEqual({
      fields: [
        { path: ['a'], text: 'one' },
        { path: ['b', '0'], text: 'two' },
        { path: ['b', '2', 'c'], text: 'three' },
      ],
      truncated: false,
    });
  });

  it('reads a leaf at the depth bound and truncates one below it', () => {
    expect(scannableFields(nested(RESULT_WALK_MAX_DEPTH))).toEqual({
      fields: [{ path: Array<string>(RESULT_WALK_MAX_DEPTH).fill('k'), text: 'x' }],
      truncated: false,
    });
    expect(scannableFields(nested(RESULT_WALK_MAX_DEPTH + 1))).toEqual({
      fields: [],
      truncated: true,
    });
  });

  it('does not count an empty container past the depth bound as truncated', () => {
    expect(scannableFields(nested(RESULT_WALK_MAX_DEPTH + 1, {}))).toEqual({
      fields: [],
      truncated: false,
    });
  });

  it('truncates past the leaf-count bound', () => {
    const atBound = Array.from({ length: RESULT_WALK_MAX_LEAVES }, (_, i) => `v${String(i)}`);
    const inside = scannableFields(atBound);
    expect(inside.truncated).toBe(false);
    expect(inside.fields.map((field) => field.text)).toEqual(atBound);
    const past = scannableFields([...atBound, 'one more']);
    expect(past.fields).toHaveLength(RESULT_WALK_MAX_LEAVES);
    expect(past.truncated).toBe(true);
  });

  it('reads a leaf of exactly the per-leaf bound whole', () => {
    const atCap = 'a'.repeat(RESULT_WALK_MAX_LEAF_CHARS);
    expect(scannableFields({ atCap })).toEqual({
      fields: [{ path: ['atCap'], text: atCap }],
      truncated: false,
    });
  });

  it('truncates a leaf longer than the per-leaf bound', () => {
    const long = 'a'.repeat(RESULT_WALK_MAX_LEAF_CHARS + 1);
    const result = scannableFields({ short: 'kept', long });
    expect(result.fields).toEqual([{ path: ['short'], text: 'kept' }]);
    expect(result.truncated).toBe(true);
  });

  it('truncates once the leaves add up past the total bound', () => {
    const leaf = 'b'.repeat(RESULT_WALK_MAX_LEAF_CHARS);
    const count = Math.floor(RESULT_WALK_MAX_TOTAL_CHARS / RESULT_WALK_MAX_LEAF_CHARS);
    const atBound = Array.from({ length: count }, () => leaf);
    const inside = scannableFields(atBound);
    expect(inside.truncated).toBe(false);
    expect(inside.fields).toHaveLength(count);
    expect(inside.fields.every((field) => field.text === leaf)).toBe(true);
    const past = scannableFields([...atBound, 'c']);
    expect(past.fields).toHaveLength(count);
    expect(past.truncated).toBe(true);
  });
});
