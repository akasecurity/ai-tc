import { describe, expect, it } from 'vitest';

import { extractCsv } from './csv.ts';

describe('extractCsv', () => {
  it('parses a simple CSV into columns, rows, and header-prefixed text', () => {
    const input = 'first_name,dob\nAlice,1985-03-22\nBob,1990-07-01';
    const result = extractCsv(input);

    expect(result.columns).toEqual(['first_name', 'dob']);
    expect(result.rows).toEqual([
      ['Alice', '1985-03-22'],
      ['Bob', '1990-07-01'],
    ]);
    expect(result.text).toBe(
      'first_name: Alice | dob: 1985-03-22\nfirst_name: Bob | dob: 1990-07-01',
    );
  });

  it('places each header adjacent to its value in text (proximity cue)', () => {
    const result = extractCsv('first_name,dob\nAlice,1985-03-22');
    expect(result.text).toContain('first_name: Alice');
    expect(result.text).toContain('dob: 1985-03-22');
  });

  it('handles quoted fields containing the delimiter', () => {
    const input = 'name,note\n"Doe, John","hello, world"';
    const result = extractCsv(input);

    expect(result.columns).toEqual(['name', 'note']);
    expect(result.rows).toEqual([['Doe, John', 'hello, world']]);
    expect(result.text).toBe('name: Doe, John | note: hello, world');
  });

  it('handles doubled-quote escapes inside quoted fields', () => {
    const input = 'name,quote\nAlice,"She said ""hi"" loudly"';
    const result = extractCsv(input);

    expect(result.rows).toEqual([['Alice', 'She said "hi" loudly']]);
  });

  it('handles CRLF line endings', () => {
    const input = 'a,b\r\n1,2\r\n3,4';
    const result = extractCsv(input);

    expect(result.columns).toEqual(['a', 'b']);
    expect(result.rows).toEqual([
      ['1', '2'],
      ['3', '4'],
    ]);
  });

  it('handles newlines inside quoted fields', () => {
    const input = 'name,addr\nAlice,"123 Main St\nApt 4"';
    const result = extractCsv(input);

    expect(result.rows).toEqual([['Alice', '123 Main St\nApt 4']]);
  });

  it('treats a single line as headerless data with positional columns', () => {
    const result = extractCsv('Alice,1985-03-22');

    expect(result.columns).toEqual(['col1', 'col2']);
    expect(result.rows).toEqual([['Alice', '1985-03-22']]);
    expect(result.text).toBe('col1: Alice | col2: 1985-03-22');
  });

  it('supports a custom delimiter', () => {
    const result = extractCsv('a;b\n1;2', { delimiter: ';' });

    expect(result.columns).toEqual(['a', 'b']);
    expect(result.rows).toEqual([['1', '2']]);
  });

  it('treats a quote in the middle of an unquoted field as a literal character', () => {
    // Regression: a `"` only opens a quoted field at the START of a field; a quote
    // mid-field (e.g. `a"b",c`) must be kept literally, not toggle quoting.
    const result = extractCsv('col_a,col_b\na"b",c');
    expect(result.rows).toEqual([['a"b"', 'c']]);
  });

  it('rejects a delimiter that is not exactly one character', () => {
    expect(() => extractCsv('a,b\n1,2', { delimiter: ',,' })).toThrow();
    expect(() => extractCsv('a,b\n1,2', { delimiter: '' })).toThrow();
  });

  it('falls back to colN in text when a header cell is empty', () => {
    const result = extractCsv('a,,c\n1,2,3');
    expect(result.columns).toEqual(['a', '', 'c']);
    expect(result.text).toBe('a: 1 | col2: 2 | c: 3');
  });

  it('returns an empty result for empty input', () => {
    expect(extractCsv('')).toEqual({ columns: [], rows: [], text: '' });
  });

  it('ignores a trailing newline rather than emitting an empty row', () => {
    const result = extractCsv('a,b\n1,2\n');
    expect(result.rows).toEqual([['1', '2']]);
  });
});
