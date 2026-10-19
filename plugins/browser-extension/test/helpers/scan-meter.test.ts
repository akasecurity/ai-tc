import { describe, expect, it } from 'vitest';

import { charactersExamined } from './scan-meter.ts';

// The rescan guard in stream-assembler.test.ts is only as good as this count,
// so each charge it makes is pinned here: a meter that stopped counting one
// kind of read would leave that guard green over a rescan written that way.
describe('charactersExamined', () => {
  const text = 'abcdefghij';

  it('charges a character accessor one per call', () => {
    expect(
      charactersExamined(() => {
        for (let i = 0; i < text.length; i += 1) text.charCodeAt(i);
      }),
    ).toBe(text.length);
  });

  it('charges a search the rest of the string from where it starts', () => {
    expect(charactersExamined(() => text.indexOf('z'))).toBe(10);
    expect(charactersExamined(() => text.indexOf('z', 4))).toBe(6);
    expect(charactersExamined(() => text.includes('z'))).toBe(10);
  });

  it('charges a prefix test the length it compares', () => {
    expect(charactersExamined(() => text.startsWith('abc'))).toBe(3);
  });

  it('charges a regex run the input from its last index, once per run', () => {
    expect(charactersExamined(() => /z+/.test(text))).toBe(10);
    expect(charactersExamined(() => text.search(/z+/))).toBe(10);
    expect(charactersExamined(() => text.split('e'))).toBe(10);
    const global = /z+/g;
    global.lastIndex = 7;
    expect(charactersExamined(() => global.exec(text))).toBe(3);
  });

  it('charges iteration each character it yields', () => {
    let seen = '';
    expect(
      charactersExamined(() => {
        for (const char of text) seen += char;
      }),
    ).toBe(text.length);
    expect(seen).toBe(text);
    expect(charactersExamined(() => Array.from(text))).toBe(text.length);
    // A loop that stops early is charged only what it read.
    expect(
      charactersExamined(() => {
        for (const char of text) if (char === 'c') break;
      }),
    ).toBe(3);
  });

  it('does not charge a copy', () => {
    expect(charactersExamined(() => [text.slice(2), text.concat(text)].join(''))).toBe(0);
  });

  it('leaves the builtins as it found them, including when the work throws', () => {
    const builtins = (): unknown[] => [
      Object.getOwnPropertyDescriptor(String.prototype, 'indexOf')?.value,
      Object.getOwnPropertyDescriptor(RegExp.prototype, 'exec')?.value,
      Object.getOwnPropertyDescriptor(String.prototype, Symbol.iterator)?.value,
    ];
    const before = builtins();
    expect(() =>
      charactersExamined(() => {
        throw new Error('the work failed');
      }),
    ).toThrow('the work failed');
    expect(builtins()).toEqual(before);
    expect(charactersExamined(() => undefined)).toBe(0);
  });
});
