import { describe, expect, it } from 'vitest';

import { parseJsonc, removeProperty, setProperty } from '../src/jsonc-edit.ts';

/** A settings.json the way people actually keep one: comments and a trailing comma. */
const SETTINGS = `{
    // Editor
    "editor.fontSize": 14, // personal
    /* block
       comment */
    "files.exclude": {
        "**/.git": true, // keep
    },
    "url": "http://example.test/a//b",
}
`;

describe('parseJsonc', () => {
  it('reads comments, trailing commas and slashes inside strings', () => {
    expect(parseJsonc(SETTINGS)).toEqual({
      'editor.fontSize': 14,
      'files.exclude': { '**/.git': true },
      url: 'http://example.test/a//b',
    });
  });

  it('reads an empty document as an empty object', () => {
    expect(parseJsonc('')).toEqual({});
    expect(parseJsonc('  \n')).toEqual({});
  });

  it('reads a document of only comments as an empty object', () => {
    expect(parseJsonc('// my settings\n')).toEqual({});
    expect(parseJsonc('/* nothing yet */')).toEqual({});
  });

  // An edit to the first copy of a key while JSON.parse reads the last would
  // report a change that never applies.
  it('refuses a top-level key that appears twice', () => {
    const doubled = '{"chat.useHooks": false, "chat.useHooks": false}';
    expect(() => parseJsonc(doubled)).toThrow(/"chat\.useHooks" appears more than once/u);
    expect(() => setProperty(doubled, 'chat.useHooks', true)).toThrow(/appears more than once/u);
    expect(parseJsonc('{"a": {"x": 1}, "b": {"x": 2}}')).toEqual({ a: { x: 1 }, b: { x: 2 } });
  });

  it('refuses what it cannot edit safely', () => {
    for (const bad of ['[]', '{', '{"a": 1} x', '{"a" 1}', '{"a": "x}', '{/* x', '42']) {
      expect(() => parseJsonc(bad), bad).toThrow();
    }
  });
});

describe('setProperty', () => {
  it('appends a new property and keeps every other line, comments included', () => {
    const next = setProperty(SETTINGS, 'chat.useHooks', true);
    expect(parseJsonc(next)['chat.useHooks']).toBe(true);
    for (const line of SETTINGS.split('\n').slice(0, 9)) expect(next).toContain(line);
    expect(next).toContain('    "chat.useHooks": true');
  });

  it('appends after a last property with no trailing comma', () => {
    const next = setProperty('{\n  "a": 1 // note\n}\n', 'b', 2);
    expect(next).toBe('{\n  "a": 1, // note\n  "b": 2\n}\n');
    expect(parseJsonc(next)).toEqual({ a: 1, b: 2 });
  });

  it('replaces an existing value in place', () => {
    const next = setProperty(SETTINGS, 'editor.fontSize', 16);
    expect(next).toContain('"editor.fontSize": 16, // personal');
    expect(parseJsonc(next)['editor.fontSize']).toBe(16);
  });

  it('replaces an object value with the object indented under its key', () => {
    const next = setProperty(SETTINGS, 'files.exclude', { a: true });
    expect(next).toContain('"files.exclude": {\n        "a": true\n    },');
    expect(parseJsonc(next)['files.exclude']).toEqual({ a: true });
  });

  it('creates a document from nothing, and fills an empty object', () => {
    expect(parseJsonc(setProperty('', 'a', 1))).toEqual({ a: 1 });
    expect(setProperty('{}', 'a', 1)).toBe('{\n    "a": 1\n}');
  });

  it('only touches top-level keys', () => {
    const next = setProperty(SETTINGS, '**/.git', false);
    expect(parseJsonc(next)['files.exclude']).toEqual({ '**/.git': true });
    expect(parseJsonc(next)['**/.git']).toBe(false);
  });
});

describe('setProperty on a document of only comments', () => {
  it('keeps the comments and adds the object after them', () => {
    const next = setProperty('// my settings\n', 'chat.useHooks', true);
    expect(next.startsWith('// my settings\n')).toBe(true);
    expect(parseJsonc(next)).toEqual({ 'chat.useHooks': true });
  });
});

describe('a comma after a comment that follows the value', () => {
  it('is reused when appending, so no second comma is added', () => {
    const next = setProperty('{\n  "a": 1 /* c */,\n}', 'b', true);
    expect(next).toBe('{\n  "a": 1 /* c */,\n  "b": true\n}');
    expect(parseJsonc(next)).toEqual({ a: 1, b: true });
  });
});

describe('a document starting with a byte-order mark', () => {
  it('parses as VS Code reads it, and an edit keeps the mark', () => {
    expect(parseJsonc('\uFEFF{"a":1}')).toEqual({ a: 1 });
    const next = setProperty('\uFEFF{\n  "a": 1\n}\n', 'b', true);
    expect(next.startsWith('\uFEFF{')).toBe(true);
    expect(parseJsonc(next)).toEqual({ a: 1, b: true });
  });
});

describe('a CRLF document', () => {
  const CRLF = '{\r\n  "files.exclude": {}\r\n}\r\n';

  it('appends with the document’s own line ending', () => {
    const next = setProperty(CRLF, 'chat.useHooks', true);
    expect(next).toBe('{\r\n  "files.exclude": {},\r\n  "chat.useHooks": true\r\n}\r\n');
    expect(next.replaceAll('\r\n', '')).not.toContain('\n');
  });

  it('indents an object value with CRLF continuation lines', () => {
    const next = setProperty(CRLF, 'files.exclude', { a: true });
    expect(next.replaceAll('\r\n', '')).not.toContain('\n');
    expect(parseJsonc(next)).toEqual({ 'files.exclude': { a: true } });
  });

  it('removes a property with its whole line, leaving no stray carriage return', () => {
    expect(removeProperty(CRLF, 'files.exclude')).toBe('{\r\n}\r\n');
  });
});

describe('removeProperty', () => {
  it.each([
    ['a block comment', '{\n  "a": 1 /* note */, "b": 2\n}\n'],
    ['a line comment', '{\n  "a": 1 // note\n  , "b": 2\n}\n'],
  ])('removes the comma that follows %s after the value', (_name, text) => {
    const next = removeProperty(text, 'a');
    expect(parseJsonc(next)).toEqual({ b: 2 });
    expect(next).not.toContain('note');
  });

  it('leaves a document of only comments alone', () => {
    expect(removeProperty('// my settings\n', 'a')).toBe('// my settings\n');
  });

  it('removes a middle property and its line', () => {
    const next = removeProperty(SETTINGS, 'files.exclude');
    expect(parseJsonc(next)).toEqual({ 'editor.fontSize': 14, url: 'http://example.test/a//b' });
    expect(next).toContain('// Editor');
  });

  it('removes the last property and the comma before it', () => {
    const next = removeProperty('{\n  "a": 1,\n  "b": 2\n}\n', 'b');
    expect(next).toBe('{\n  "a": 1\n}\n');
  });

  it('leaves the text alone when the key is absent', () => {
    expect(removeProperty(SETTINGS, 'nope')).toBe(SETTINGS);
    expect(removeProperty('', 'nope')).toBe('');
  });
});
