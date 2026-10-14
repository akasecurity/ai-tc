import { describe, expect, it } from 'vitest';

import { withoutScopeKey } from '../../src/attached/scope-strip.ts';

// The shape the helper is generic over, spelled once so `attributes` stays
// optional on what comes back, which is what the empty-bag case returns.
interface Row {
  id: string;
  attributes?: Record<string, unknown>;
}

describe('withoutScopeKey', () => {
  it('drops the scope key and keeps every other attribute, in order', () => {
    const row: Row = {
      id: 'e',
      attributes: { cwd: '/w', scope_key: 'github.com/o/r', repo: 'o/r' },
    };
    const out = withoutScopeKey(row);
    expect(out).toEqual({ id: 'e', attributes: { cwd: '/w', repo: 'o/r' } });
    // Order is part of the bytes a receiver's idempotency sees.
    expect(Object.keys(out.attributes ?? {})).toEqual(['cwd', 'repo']);
  });

  // A bare row a producer stamped (an attribute-less session stub) must forward
  // exactly what it forwarded before it was stamped: no `attributes: {}` left over.
  it('drops the attributes member when the scope key was its only entry', () => {
    const out = withoutScopeKey<Row>({ id: 'e', attributes: { scope_key: 'github.com/o/r' } });
    expect(out).toEqual({ id: 'e' });
    expect(out).not.toHaveProperty('attributes');
  });

  // The input is what the local store holds and what gets stamped delivered;
  // changing it would change a local row to make a wire body.
  it('never mutates its input', () => {
    const attributes = { cwd: '/w', scope_key: 'github.com/o/r' };
    const row: Row = { id: 'e', attributes };
    withoutScopeKey(row);
    expect(row.attributes).toBe(attributes);
    expect(attributes).toEqual({ cwd: '/w', scope_key: 'github.com/o/r' });
  });

  // Byte identity for every row that was never stamped, and an empty bag a
  // producer wrote is NOT dropped: only an emptiness the strip itself caused is.
  it('returns the input itself when there is nothing to strip', () => {
    const bare: Row = { id: 'a' };
    const plain: Row = { id: 'b', attributes: { cwd: '/w' } };
    const empty: Row = { id: 'c', attributes: {} };
    expect(withoutScopeKey(bare)).toBe(bare);
    expect(withoutScopeKey(plain)).toBe(plain);
    expect(withoutScopeKey(empty)).toBe(empty);
  });

  // It is the MEMBER that is local, not a well-formed value of it: a damaged
  // bag must not forward the member just because its value is not a string.
  it('drops a scope key whose value is not a string', () => {
    const out = withoutScopeKey<Row>({ id: 'e', attributes: { scope_key: 42, repo: 'o/r' } });
    expect(out.attributes).toEqual({ repo: 'o/r' });
  });
});
