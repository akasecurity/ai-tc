import { describe, expect, it } from 'vitest';

import { replaceResponseField, scannableResponseFields } from '../../src/hooks/tool-response.ts';

describe('scannableResponseFields', () => {
  it('treats a plain-string response as one scannable field at the root', () => {
    expect(scannableResponseFields('Bash', 'some output')).toEqual([
      { path: [], text: 'some output' },
    ]);
  });

  it('extracts file.content from a structured Read response', () => {
    const response = {
      type: 'text',
      file: {
        filePath: '/tmp/proj/notes.txt',
        content: 'first line\nsecond line\n',
        numLines: 2,
        startLine: 1,
        totalLines: 2,
      },
    };
    expect(scannableResponseFields('Read', response)).toEqual([
      { path: ['file', 'content'], text: 'first line\nsecond line\n' },
    ]);
  });

  it('extracts stdout and stderr from a structured Bash response', () => {
    const response = {
      stdout: 'out text',
      stderr: 'err text',
      interrupted: false,
      isImage: false,
    };
    expect(scannableResponseFields('Bash', response)).toEqual([
      { path: ['stdout'], text: 'out text' },
      { path: ['stderr'], text: 'err text' },
    ]);
  });

  it('skips empty strings so hooks do not scan or rewrite blank fields', () => {
    const response = { stdout: 'out', stderr: '', interrupted: false, isImage: false };
    expect(scannableResponseFields('Bash', response)).toEqual([{ path: ['stdout'], text: 'out' }]);
  });

  it('extracts result from a structured WebFetch response', () => {
    const response = {
      bytes: 100,
      code: 200,
      codeText: 'OK',
      result: 'page text',
      durationMs: 5,
      url: 'https://example.com',
    };
    expect(scannableResponseFields('WebFetch', response)).toEqual([
      { path: ['result'], text: 'page text' },
    ]);
  });

  it('returns nothing for tools without a known response shape', () => {
    expect(scannableResponseFields('Glob', { filenames: ['a.ts'] })).toEqual([]);
  });

  it('returns nothing when the expected field is missing or not a string', () => {
    expect(scannableResponseFields('Read', { type: 'image', file: { base64: 'x' } })).toEqual([]);
    expect(scannableResponseFields('Bash', { stdout: 42 })).toEqual([]);
    expect(scannableResponseFields('Read', null)).toEqual([]);
    expect(scannableResponseFields('Read', undefined)).toEqual([]);
  });

  it('does not resolve Object.prototype members as path tables', () => {
    // A bare index lookup would return e.g. Object.prototype.constructor (a
    // non-iterable function, not caught by ??) and crash the for-of.
    expect(scannableResponseFields('constructor', { stdout: 'x' })).toEqual([]);
    expect(scannableResponseFields('toString', { stdout: 'x' })).toEqual([]);
    expect(scannableResponseFields('hasOwnProperty', { stdout: 'x' })).toEqual([]);
  });
});

describe('replaceResponseField', () => {
  it('replaces the whole response when the path is the root', () => {
    expect(replaceResponseField('original text', [], '[replaced]')).toBe('[replaced]');
  });

  it('replaces a nested field while preserving the rest of the response shape', () => {
    const response = {
      type: 'text',
      file: {
        filePath: '/tmp/proj/notes.txt',
        content: 'original content\n',
        numLines: 1,
        startLine: 1,
        totalLines: 1,
      },
    };
    const updated = replaceResponseField(response, ['file', 'content'], 'rewritten content\n');
    expect(updated).toEqual({
      type: 'text',
      file: {
        filePath: '/tmp/proj/notes.txt',
        content: 'rewritten content\n',
        numLines: 1,
        startLine: 1,
        totalLines: 1,
      },
    });
    // The original is untouched — hooks may still need the raw text afterwards.
    expect(response.file.content).toBe('original content\n');
  });

  it('replaces a top-level field without disturbing siblings', () => {
    const response = { stdout: 'to rewrite', stderr: 'keep', interrupted: false };
    expect(replaceResponseField(response, ['stdout'], '[withheld]')).toEqual({
      stdout: '[withheld]',
      stderr: 'keep',
      interrupted: false,
    });
  });
});
