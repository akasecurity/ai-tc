import { TIME_RANGES } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  BLOCKED_WINDOWS,
  DEFAULT_BLOCKED_WINDOW,
  DEFAULT_TIME_RANGE,
  resolveBlockedWindow,
  TIME_RANGE_OPTIONS,
} from '../../src/lib/timeRanges.ts';

// The values live in the schema and the labels live here, so a range added
// upstream can arrive without a label. These pin the two lists together.
describe('TIME_RANGE_OPTIONS', () => {
  it('labels every range the schema defines, in the same order', () => {
    expect(TIME_RANGE_OPTIONS.map((r) => r.value)).toEqual([...TIME_RANGES]);
  });

  it('gives every option a non-empty label', () => {
    for (const option of TIME_RANGE_OPTIONS) {
      expect(option.label.trim()).not.toBe('');
    }
  });

  it('can render the default as a selected chip', () => {
    expect(TIME_RANGE_OPTIONS.map((r) => r.value)).toContain(DEFAULT_TIME_RANGE);
  });
});

describe('resolveBlockedWindow', () => {
  it('accepts every valid window value', () => {
    for (const { value } of BLOCKED_WINDOWS) {
      expect(resolveBlockedWindow(value)).toBe(value);
    }
  });

  it('falls back to the default for an undefined or unknown value', () => {
    expect(resolveBlockedWindow(undefined)).toBe(DEFAULT_BLOCKED_WINDOW);
    expect(resolveBlockedWindow('')).toBe(DEFAULT_BLOCKED_WINDOW);
    expect(resolveBlockedWindow('7d')).toBe(DEFAULT_BLOCKED_WINDOW);
  });

  it('rejects inherited Object.prototype keys (no prototype-chain leak)', () => {
    // `in` would let these through and resolve to a function/inherited value;
    // Object.hasOwn does not.
    for (const key of ['toString', 'constructor', 'hasOwnProperty', '__proto__', 'valueOf']) {
      expect(resolveBlockedWindow(key)).toBe(DEFAULT_BLOCKED_WINDOW);
    }
  });
});
