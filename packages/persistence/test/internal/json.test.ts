import { describe, expect, it } from 'vitest';

import { parseJsonObject, safeJson } from '../../src/internal/json.ts';

describe('safeJson', () => {
  it('parses valid JSON of any shape', () => {
    expect(safeJson('{"a":1}', {})).toEqual({ a: 1 });
    expect(safeJson('[1,2]', [])).toEqual([1, 2]);
    expect(safeJson('42', 0)).toBe(42);
    expect(safeJson('"s"', '')).toBe('s');
  });

  it('returns the fallback for null, undefined, empty, and malformed input', () => {
    const fallback = { d: true };
    expect(safeJson(null, fallback)).toBe(fallback);
    expect(safeJson(undefined, fallback)).toBe(fallback);
    expect(safeJson('', fallback)).toBe(fallback);
    expect(safeJson('{nope', fallback)).toBe(fallback);
  });

  it('returns the exact fallback reference, not a copy', () => {
    const fallback: string[] = [];
    expect(safeJson<string[]>(null, fallback)).toBe(fallback);
    expect(safeJson<string[]>('not json', fallback)).toBe(fallback);
  });
});

describe('parseJsonObject', () => {
  it('returns a parsed non-null object', () => {
    expect(parseJsonObject('{"provider":"anthropic"}')).toEqual({ provider: 'anthropic' });
    expect(parseJsonObject('{}')).toEqual({});
  });

  it('returns undefined for scalars and JSON null', () => {
    expect(parseJsonObject('42')).toBeUndefined();
    expect(parseJsonObject('"s"')).toBeUndefined();
    expect(parseJsonObject('true')).toBeUndefined();
    expect(parseJsonObject('null')).toBeUndefined();
  });

  it('returns undefined for null, undefined, empty, and malformed input', () => {
    expect(parseJsonObject(null)).toBeUndefined();
    expect(parseJsonObject(undefined)).toBeUndefined();
    expect(parseJsonObject('')).toBeUndefined();
    expect(parseJsonObject('{nope')).toBeUndefined();
  });

  it('passes arrays through (they satisfy the non-null object check)', () => {
    expect(parseJsonObject('[1,2]')).toEqual([1, 2]);
  });
});
