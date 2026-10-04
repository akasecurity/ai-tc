import { describe, expect, it } from 'vitest';

import {
  MCP_RESPONSE_MAX_BLOCK_CHARS,
  MCP_RESPONSE_MAX_BLOCKS,
  MCP_RESPONSE_MAX_TOTAL_CHARS,
  replaceResponseField,
  scannableResponseFields,
} from '../../src/hooks/tool-response.ts';

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

describe('scannableResponseFields — Grep', () => {
  it('extracts content from a content-mode Grep response', () => {
    const response = {
      mode: 'content',
      numFiles: 0,
      filenames: [],
      content: 'src/a.ts:3:const value = 1;',
      numLines: 1,
      totalLines: 1,
    };
    expect(scannableResponseFields('Grep', response)).toEqual([
      { path: ['content'], text: 'src/a.ts:3:const value = 1;' },
    ]);
  });

  it('returns nothing for a files_with_matches response, which carries no content', () => {
    const response = { mode: 'files_with_matches', numFiles: 1, filenames: ['src/a.ts'] };
    expect(scannableResponseFields('Grep', response)).toEqual([]);
  });

  it('treats a plain-string Grep response as one root field', () => {
    expect(scannableResponseFields('Grep', 'No files found')).toEqual([
      { path: [], text: 'No files found' },
    ]);
  });
});

describe('scannableResponseFields — mcp__* tools', () => {
  const tool = 'mcp__reader__read_url';

  it('extracts every text block of a bare content-block array', () => {
    const response = [
      { type: 'text', text: 'first page section' },
      { type: 'text', text: 'second page section' },
    ];
    expect(scannableResponseFields(tool, response)).toEqual([
      { path: [0, 'text'], text: 'first page section' },
      { path: [1, 'text'], text: 'second page section' },
    ]);
  });

  it('extracts text blocks wrapped under content', () => {
    const response = {
      content: [{ type: 'text', text: 'wrapped text' }],
      isError: false,
    };
    expect(scannableResponseFields(tool, response)).toEqual([
      { path: ['content', 0, 'text'], text: 'wrapped text' },
    ]);
  });

  it('treats a plain-string MCP response as one root field', () => {
    expect(scannableResponseFields(tool, 'plain result')).toEqual([
      { path: [], text: 'plain result' },
    ]);
  });

  it('ignores non-text blocks, empty text, and malformed entries while keeping indices', () => {
    const response = [
      { type: 'image', data: 'aGVsbG8=', mimeType: 'image/png' },
      { type: 'resource', resource: { uri: 'memo://notes/x', text: 'resource body' } },
      { type: 'text', text: '' },
      { type: 'text', text: 42 },
      null,
      'stray string',
      ['nested'],
      { text: 'no type field' },
      { type: 'text', text: 'kept' },
    ];
    expect(scannableResponseFields(tool, response)).toEqual([{ path: [8, 'text'], text: 'kept' }]);
  });

  it('returns nothing for an object that does not wrap a content array', () => {
    expect(scannableResponseFields(tool, { result: 'x' })).toEqual([]);
    expect(scannableResponseFields(tool, { content: 'not an array' })).toEqual([]);
    expect(scannableResponseFields(tool, null)).toEqual([]);
    expect(scannableResponseFields(tool, 7)).toEqual([]);
  });

  it('does not read an inherited content property', () => {
    const response = Object.create({ content: [{ type: 'text', text: 'inherited' }] }) as object;
    expect(scannableResponseFields(tool, response)).toEqual([]);
  });

  it('caps the number of scanned blocks', () => {
    const response = Array.from({ length: MCP_RESPONSE_MAX_BLOCKS + 50 }, (_, i) => ({
      type: 'text',
      text: `block ${String(i)}`,
    }));
    const fields = scannableResponseFields(tool, response);
    expect(fields).toHaveLength(MCP_RESPONSE_MAX_BLOCKS);
    expect(fields.at(-1)?.path).toEqual([MCP_RESPONSE_MAX_BLOCKS - 1, 'text']);
  });

  it('skips a block longer than the per-block cap but scans its siblings', () => {
    const response = [
      { type: 'text', text: 'x'.repeat(MCP_RESPONSE_MAX_BLOCK_CHARS + 1) },
      { type: 'text', text: 'after the oversized block' },
    ];
    expect(scannableResponseFields(tool, response)).toEqual([
      { path: [1, 'text'], text: 'after the oversized block' },
    ]);
  });

  it('stops once the total character budget is spent', () => {
    const perBlock = MCP_RESPONSE_MAX_BLOCK_CHARS;
    const fitting = Math.floor(MCP_RESPONSE_MAX_TOTAL_CHARS / perBlock);
    const response = Array.from({ length: fitting + 2 }, () => ({
      type: 'text',
      text: 'y'.repeat(perBlock),
    }));
    const fields = scannableResponseFields(tool, response);
    expect(fields).toHaveLength(fitting);
    const total = fields.reduce((sum, field) => sum + field.text.length, 0);
    expect(total).toBeLessThanOrEqual(MCP_RESPONSE_MAX_TOTAL_CHARS);
  });

  it('applies the block walk only to the mcp__ prefix', () => {
    const response = [{ type: 'text', text: 'not an mcp tool' }];
    expect(scannableResponseFields('mcp_reader', response)).toEqual([]);
    expect(scannableResponseFields('Glob', response)).toEqual([]);
  });
});

describe('replaceResponseField', () => {
  it('rewrites one MCP text block in place, keeping the array and sibling blocks', () => {
    const response = [
      { type: 'text', text: 'clean' },
      { type: 'text', text: 'to rewrite' },
      { type: 'image', data: 'aGVsbG8=', mimeType: 'image/png' },
    ];
    const updated = replaceResponseField(response, [1, 'text'], '[redacted]');
    expect(Array.isArray(updated)).toBe(true);
    expect(updated).toEqual([
      { type: 'text', text: 'clean' },
      { type: 'text', text: '[redacted]' },
      { type: 'image', data: 'aGVsbG8=', mimeType: 'image/png' },
    ]);
    expect(response[1]?.text).toBe('to rewrite');
  });

  it('rewrites a wrapped MCP text block in place', () => {
    const response = { content: [{ type: 'text', text: 'to rewrite' }], isError: false };
    expect(replaceResponseField(response, ['content', 0, 'text'], '[redacted]')).toEqual({
      content: [{ type: 'text', text: '[redacted]' }],
      isError: false,
    });
  });

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
