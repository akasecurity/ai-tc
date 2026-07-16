import { describe, expect, it } from 'vitest';

import { computeResolutions } from '../src/resolve.ts';

describe('computeResolutions', () => {
  it('returns keys in prior but not in current', () => {
    expect(computeResolutions(['a', 'b'], ['b'])).toEqual(['a']);
  });

  it('returns empty array when all prior keys are in current', () => {
    expect(computeResolutions(['a'], ['a'])).toEqual([]);
  });

  it('returns empty array when prior is empty', () => {
    expect(computeResolutions([], ['a'])).toEqual([]);
  });

  it('deduplicates prior before filtering', () => {
    expect(computeResolutions(['a', 'a'], [])).toEqual(['a']);
  });
});
