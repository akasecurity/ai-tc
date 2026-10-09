import { describe, expect, it } from 'vitest';

import { stripInvisiblePadding } from '../src/invisible-padding.ts';

const cp = (n: number): string => String.fromCodePoint(n);

describe('stripInvisiblePadding', () => {
  it.each([
    ['zero width space', 0x200b],
    ['word joiner', 0x2060],
    ['invisible math operator', 0x2062],
    ['byte-order mark', 0xfeff],
    ['soft hyphen', 0x00ad],
    ['bidi override', 0x202e],
    ['bidi isolate', 0x2067],
    ['tag begin', 0xe0001],
    ['tag letter', 0xe0041],
    ['left-to-right mark', 0x200e],
    ['right-to-left mark', 0x200f],
    ['Mongolian vowel separator', 0x180e],
    ['interlinear annotation anchor', 0xfff9],
    ['interlinear annotation separator', 0xfffa],
    ['interlinear annotation terminator', 0xfffb],
  ])('removes a %s', (_name, point) => {
    expect(stripInvisiblePadding(`ab${cp(point)}cd`)).toBe('abcd');
  });

  it.each([
    ['zero width joiner', 0x200d],
    ['zero width non-joiner', 0x200c],
    ['Arabic number sign (visible Cf)', 0x0600],
    ['variation selector', 0xfe0f],
    ['object replacement character', 0xfffc],
    ['space', 0x20],
    ['no-break space', 0xa0],
  ])('keeps a %s', (_name, point) => {
    const text = `ab${cp(point)}cd`;
    expect(stripInvisiblePadding(text)).toBe(text);
  });

  it('removes repeated padding and is stable across calls', () => {
    const padded = `${cp(0x200b)}a${cp(0x200b)}${cp(0xfeff)}b`;
    expect(stripInvisiblePadding(padded)).toBe('ab');
    expect(stripInvisiblePadding(padded)).toBe('ab');
  });
});
