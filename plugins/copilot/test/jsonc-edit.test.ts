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

describe('removeProperty', () => {
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
