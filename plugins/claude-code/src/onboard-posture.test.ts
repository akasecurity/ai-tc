import { describe, expect, it } from 'vitest';

import { parsePosture } from './onboard-posture.ts';

describe('parsePosture', () => {
  it('accepts a valid per-category palette map', () => {
    const p = parsePosture('{"secret":"warn","code_context":"monitor","pii":"block"}');
    expect(p).toEqual({ secret: 'warn', code_context: 'monitor', pii: 'block' });
  });
  it('rejects an unknown category', () => {
    expect(() => parsePosture('{"not_a_category":"warn"}')).toThrow();
  });
  it('rejects a non-palette action (e.g. log/allow)', () => {
    expect(() => parsePosture('{"secret":"log"}')).toThrow();
    expect(() => parsePosture('{"secret":"allow"}')).toThrow();
  });
  it('rejects malformed JSON', () => {
    expect(() => parsePosture('{secret:warn}')).toThrow();
  });
  it('rejects an empty object / array (nothing to write)', () => {
    expect(() => parsePosture('{}')).toThrow();
    expect(() => parsePosture('[]')).toThrow();
  });
});
