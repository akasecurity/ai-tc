// What this pins: the write-back must hand Claude Code the payload shape it
// gave us. Claude Code validates a hook's updatedInput/updatedToolOutput
// against the tool's own schema and silently falls back to the ORIGINAL
// payload on a mismatch — so a spine rebuilt with the wrong container type
// doesn't fail loudly, it runs the unredacted arguments. The array cases below
// are the ones that regressed the moment MultiEdit (edits[i].new_string)
// became scannable.
import { describe, expect, it } from 'vitest';

import { replaceAtPath, stringAtPath } from '../../src/hooks/paths.ts';

describe('stringAtPath', () => {
  it('reads a nested string through objects and arrays', () => {
    const root = { edits: [{ new_string: 'a' }, { new_string: 'b' }] };
    expect(stringAtPath(root, ['edits', 1, 'new_string'])).toBe('b');
  });

  it('returns the root itself for an empty path', () => {
    expect(stringAtPath('bare', [])).toBe('bare');
  });

  it('returns undefined for a non-string leaf, rather than coercing', () => {
    expect(stringAtPath({ n: 5 }, ['n'])).toBeUndefined();
    expect(stringAtPath({ o: { k: 'v' } }, ['o'])).toBeUndefined();
  });

  it('returns undefined for a path that does not resolve', () => {
    expect(stringAtPath({ a: 'x' }, ['a', 'b'])).toBeUndefined();
    expect(stringAtPath({}, ['missing'])).toBeUndefined();
    expect(stringAtPath({ list: ['x'] }, ['list', 9])).toBeUndefined();
  });

  it('does not resolve inherited members: own properties only', () => {
    // A bare index would return Object.prototype.toString here — a function,
    // so not a string leaf, but 'constructor' would walk somewhere real.
    expect(stringAtPath({}, ['toString'])).toBeUndefined();
    expect(stringAtPath({}, ['constructor', 'name'])).toBeUndefined();
  });

  it('will not index an array with a string segment', () => {
    expect(stringAtPath({ list: ['x'] }, ['list', '0'])).toBeUndefined();
  });
});

describe('replaceAtPath', () => {
  it('keeps arrays as arrays along the rebuilt spine', () => {
    // The regression this file exists for: object-spreading `edits` hands back
    // { '0': …, '1': … }, MultiEdit's schema rejects it, and Claude Code runs
    // the ORIGINAL unredacted edits.
    const root = { edits: [{ new_string: 'keep' }, { new_string: 'secret' }] };
    const out = replaceAtPath(root, ['edits', 1, 'new_string'], 'masked') as typeof root;

    expect(Array.isArray(out.edits)).toBe(true);
    expect(out.edits).toEqual([{ new_string: 'keep' }, { new_string: 'masked' }]);
  });

  it('leaves the original untouched (siblings shared by reference)', () => {
    const sibling = { new_string: 'keep', old_string: 'anchor' };
    const root = { file_path: '/a.ts', edits: [sibling, { new_string: 'secret' }] };
    const out = replaceAtPath(root, ['edits', 1, 'new_string'], 'masked') as typeof root;

    expect(root.edits[1]?.new_string).toBe('secret');
    expect(out).not.toBe(root);
    // Untouched siblings ride along by reference, not a deep copy.
    expect(out.edits[0]).toBe(sibling);
    expect(out.file_path).toBe('/a.ts');
  });

  it('replaces a top-level field, leaving the rest of the payload intact', () => {
    const out = replaceAtPath({ content: 'secret', file_path: '/a.ts' }, ['content'], 'masked');
    expect(out).toEqual({ content: 'masked', file_path: '/a.ts' });
  });

  it('returns the replacement itself for an empty path', () => {
    expect(replaceAtPath('anything', [], 'masked')).toBe('masked');
  });

  it('leaves the payload unchanged when the path does not resolve', () => {
    // Degrade to "no rewrite" rather than inventing structure: a stale path
    // must never turn a valid payload into one the tool cannot run. The spine
    // above an unresolvable segment is still rebuilt, so the result is a
    // structural equal rather than the same reference — the guarantee is that
    // nothing is added, dropped, or retyped.
    const root = { list: ['x'], keep: 'me' };
    expect(replaceAtPath(root, ['list', 9], 'masked')).toEqual(root);
    expect(replaceAtPath(root, ['list', '0'], 'masked')).toEqual(root);
    // An out-of-range index hands the array itself straight back.
    expect(replaceAtPath(root.list, [9], 'masked')).toBe(root.list);
    expect(replaceAtPath('scalar', ['a'], 'masked')).toBe('scalar');
  });

  it('never grafts a missing key on — a spurious key is a shape slip', () => {
    // The object branch must guard its key the way the array branch guards its
    // index. Ungurded, this returns { content: 'x', missing: undefined }: the
    // payload now carries a key the tool's schema doesn't declare, Claude Code
    // rejects the shape, and it runs the ORIGINAL unredacted arguments — the
    // exact failure this module exists to prevent.
    //
    // toStrictEqual, not toEqual: toEqual ignores undefined-valued keys and so
    // passes even when the key was grafted on.
    expect(replaceAtPath({ content: 'x' }, ['missing', 'deeper'], 'v')).toStrictEqual({
      content: 'x',
    });
    expect(replaceAtPath({ content: 'x' }, ['missing'], 'v')).toStrictEqual({ content: 'x' });
    expect(Object.hasOwn(replaceAtPath({ a: 1 }, ['b'], 'v') as object, 'b')).toBe(false);
  });

  it('does not reach the prototype through a __proto__ segment', () => {
    // No own '__proto__' key ⇒ nothing to replace, so the payload is unchanged
    // and the prototype is untouched either way.
    const out = replaceAtPath({}, ['__proto__'], 'masked') as Record<string, unknown>;
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();

    // JSON can carry a literal own '__proto__' key. Replacing it writes an own
    // property (computed keys don't trigger the prototype setter), so the
    // value is masked and the prototype still isn't touched.
    const carrier = JSON.parse('{"__proto__": "secret"}') as Record<string, unknown>;
    const masked = replaceAtPath(carrier, ['__proto__'], 'masked') as Record<string, unknown>;
    expect(Object.hasOwn(masked, '__proto__')).toBe(true);
    expect(masked.__proto__).toBe('masked');
    expect(Object.getPrototypeOf(masked)).toBe(Object.prototype);
  });
});
