import {
  REVIEW_VALUE_MAX_CHARS,
  REVIEW_VALUES_MAX,
  TOOL_OUTPUT_FORWARD_MIN_CHARS,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { cutForForward, reviewCandidatesOf } from '../src/forward-cut.ts';

describe('cutForForward', () => {
  it('keeps text at or under the cap whole', () => {
    expect(cutForForward('abc', 3)).toEqual({ content: 'abc' });
    expect(cutForForward('', 3)).toEqual({ content: '' });
  });

  it('keeps the first maxChars code units and names the full length', () => {
    expect(cutForForward('abcdef', 4)).toEqual({ content: 'abcd', truncatedFrom: 6 });
  });

  it('never ends on the first half of a surrogate pair', () => {
    const text = 'ab\u{1F600}cd';
    expect(cutForForward(text, 3)).toEqual({ content: 'ab', truncatedFrom: text.length });
    expect(cutForForward(text, 4)).toEqual({ content: 'ab\u{1F600}', truncatedFrom: text.length });
  });

  it('keeps a whole first character at the smallest cap the settings allow', () => {
    const text = '\u{1F600}abc';
    expect(cutForForward(text, TOOL_OUTPUT_FORWARD_MIN_CHARS)).toEqual({
      content: '\u{1F600}',
      truncatedFrom: text.length,
    });
  });
});

describe('reviewCandidatesOf', () => {
  it('keeps one per rule and value, in order', () => {
    expect(
      reviewCandidatesOf([
        { ruleId: 'r1', rawMatch: 'v1' },
        { ruleId: 'r1', rawMatch: 'v1' },
        { ruleId: 'r2', rawMatch: 'v1' },
      ]),
    ).toEqual([
      { ruleId: 'r1', value: 'v1' },
      { ruleId: 'r2', value: 'v1' },
    ]);
  });

  it('leaves out an empty value and one longer than the wire takes', () => {
    expect(
      reviewCandidatesOf([
        { ruleId: 'r', rawMatch: '' },
        { ruleId: 'r', rawMatch: 'x'.repeat(REVIEW_VALUE_MAX_CHARS + 1) },
      ]),
    ).toEqual([]);
  });

  it('stops at the wire bound', () => {
    const many = Array.from({ length: REVIEW_VALUES_MAX + 3 }, (_, i) => ({
      ruleId: 'r',
      rawMatch: `v${String(i)}`,
    }));
    expect(reviewCandidatesOf(many)).toHaveLength(REVIEW_VALUES_MAX);
  });
});
