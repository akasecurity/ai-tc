import { describe, expect, it } from 'vitest';

import { MAX_TARGET_LEN, truncateTarget } from '../src/truncate-target.ts';

const ROBOT = '\u{1F916}';
const ELLIPSIS = '…';
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

describe('truncateTarget', () => {
  it('leaves a target at or under the cap untouched', () => {
    const exact = 'x'.repeat(MAX_TARGET_LEN);
    expect(truncateTarget(exact)).toBe(exact);
    expect(truncateTarget('git status')).toBe('git status');
  });

  it('cuts a longer target at the cap and marks the cut', () => {
    const out = truncateTarget('x'.repeat(MAX_TARGET_LEN + 10));
    expect(out).toBe(`${'x'.repeat(MAX_TARGET_LEN)}${ELLIPSIS}`);
  });

  it('backs off one unit rather than split a surrogate pair at the cap', () => {
    const s = `${'x'.repeat(MAX_TARGET_LEN - 1)}${ROBOT} Generated`;
    expect(s.slice(0, MAX_TARGET_LEN)).toMatch(LONE_SURROGATE); // the premise
    const out = truncateTarget(s);
    expect(out).not.toMatch(LONE_SURROGATE);
    expect(out).toBe(`${'x'.repeat(MAX_TARGET_LEN - 1)}${ELLIPSIS}`);
  });

  it('keeps a pair that ends exactly at the cap', () => {
    const s = `${'x'.repeat(MAX_TARGET_LEN - 2)}${ROBOT} Generated`;
    expect(truncateTarget(s)).toBe(`${'x'.repeat(MAX_TARGET_LEN - 2)}${ROBOT}${ELLIPSIS}`);
  });
});
