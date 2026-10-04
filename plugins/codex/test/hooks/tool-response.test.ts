// Adapted from plugins/claude-code/src/hooks/tool-response.test.ts. Codex maps
// Bash, its built-in web tool (`webrun`) and MCP tools (`mcp__*`); the webrun
// and MCP shapes below are the ones recorded from a live codex-cli 0.160.0.
import { describe, expect, it } from 'vitest';

import {
  replaceResponseField,
  RESPONSE_CHUNK_CHARS,
  RESPONSE_MAX_CAPTURES,
  RESPONSE_MAX_TOTAL_CHARS,
  scannableResponseFields,
} from '../../src/hooks/tool-response.ts';

describe('scannableResponseFields', () => {
  it('treats a plain-string response as one scannable field at the root', () => {
    expect(scannableResponseFields('Bash', 'some output')).toEqual([
      { path: [], text: 'some output' },
    ]);
  });

  it('extracts stdout and stderr from a structured Bash response', () => {
    const response = {
      stdout: 'out text',
      stderr: 'err text',
      interrupted: false,
    };
    expect(scannableResponseFields('Bash', response)).toEqual([
      { path: ['stdout'], text: 'out text' },
      { path: ['stderr'], text: 'err text' },
    ]);
  });

  it('skips empty strings so hooks do not scan or rewrite blank fields', () => {
    const response = { stdout: 'out', stderr: '', interrupted: false };
    expect(scannableResponseFields('Bash', response)).toEqual([{ path: ['stdout'], text: 'out' }]);
  });

  it('returns nothing for tools without a known response shape', () => {
    expect(scannableResponseFields('apply_patch', { changes: {} })).toEqual([]);
    expect(scannableResponseFields('mcp__server__tool', { result: 'x' })).toEqual([]);
  });

  it('returns nothing when the expected field is missing or not a string', () => {
    expect(scannableResponseFields('Bash', { stdout: 42 })).toEqual([]);
    expect(scannableResponseFields('Bash', null)).toEqual([]);
    expect(scannableResponseFields('Bash', undefined)).toEqual([]);
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

  it('replaces a top-level field without disturbing siblings', () => {
    const response = { stdout: 'to rewrite', stderr: 'keep', interrupted: false };
    expect(replaceResponseField(response, ['stdout'], '[withheld]')).toEqual({
      stdout: '[withheld]',
      stderr: 'keep',
      interrupted: false,
    });
    // The original is untouched — hooks may still need the raw text afterwards.
    expect(response.stdout).toBe('to rewrite');
  });

  it('replaces a nested field while preserving the rest of the response shape', () => {
    const response = { output: { stdout: 'original', meta: { exitCode: 0 } } };
    const updated = replaceResponseField(response, ['output', 'stdout'], 'rewritten');
    expect(updated).toEqual({ output: { stdout: 'rewritten', meta: { exitCode: 0 } } });
  });
});

describe('scannableResponseFields — webrun and MCP content blocks', () => {
  it('scans each input_text block of a webrun result, addressed by index', () => {
    const response = [
      { type: 'input_text', text: 'first result' },
      { type: 'input_text', text: 'second result' },
    ];
    expect(scannableResponseFields('webrun', response)).toEqual([
      { path: [0, 'text'], text: 'first result' },
      { path: [1, 'text'], text: 'second result' },
    ]);
  });

  it('scans the text blocks under content of an MCP result and skips other block types', () => {
    const response = {
      content: [
        { type: 'text', text: 'Echo: probe' },
        { type: 'image', data: 'AAAA', mimeType: 'image/png' },
        { type: 'text', text: '' },
      ],
    };
    expect(scannableResponseFields('mcp__everything__echo', response)).toEqual([
      { path: ['content', 0, 'text'], text: 'Echo: probe' },
    ]);
  });

  it('accepts a bare block array from an MCP tool', () => {
    expect(scannableResponseFields('mcp__s__t', [{ type: 'text', text: 'x' }])).toEqual([
      { path: [0, 'text'], text: 'x' },
    ]);
  });

  it('does not treat a webrun-style input_text block as MCP text', () => {
    expect(scannableResponseFields('mcp__s__t', [{ type: 'input_text', text: 'x' }])).toEqual([]);
  });

  it('chunks a long block and caps the capture count and total size', () => {
    const big = 'a'.repeat(RESPONSE_CHUNK_CHARS + 1);
    expect(scannableResponseFields('webrun', [{ type: 'input_text', text: big }])).toEqual([
      {
        path: [0, 'text'],
        text: 'a'.repeat(RESPONSE_CHUNK_CHARS),
        range: { start: 0, end: RESPONSE_CHUNK_CHARS },
      },
      { path: [0, 'text'], text: 'a', range: { start: RESPONSE_CHUNK_CHARS, end: big.length } },
    ]);
    const many = Array.from({ length: RESPONSE_MAX_CAPTURES + 5 }, () => ({
      type: 'text',
      text: 'x',
    }));
    expect(scannableResponseFields('mcp__s__t', { content: many })).toHaveLength(
      RESPONSE_MAX_CAPTURES,
    );
    const huge = 'line\n'.repeat(Math.ceil((RESPONSE_MAX_TOTAL_CHARS + 10) / 5));
    const fields = scannableResponseFields('Bash', { stdout: huge, stderr: 'after' });
    expect(fields.reduce((sum, f) => sum + f.text.length, 0)).toBe(RESPONSE_MAX_TOTAL_CHARS);
    expect(fields.every((f) => f.path[0] === 'stdout')).toBe(true);
  });
});

describe('replaceResponseField — paths that do not resolve', () => {
  it('returns the response unchanged instead of grafting a key or slot on', () => {
    const response = { stdout: 'x' };
    expect(replaceResponseField(response, ['missing'], 'y')).toBe(response);
    expect(replaceResponseField(response, ['missing', 'deeper'], 'y')).toBe(response);
    const blocks = [{ type: 'text', text: 'x' }];
    expect(replaceResponseField(blocks, [3, 'text'], 'y')).toBe(blocks);
    expect(replaceResponseField(blocks, [-1, 'text'], 'y')).toBe(blocks);
  });

  it('does not follow an inherited key', () => {
    const response = Object.create({ stdout: 'inherited' }) as object;
    expect(replaceResponseField(response, ['stdout'], 'y')).toBe(response);
    expect(replaceResponseField({}, ['__proto__', 'polluted'], 'y')).toEqual({});
  });
});

describe('replaceResponseField — arrays', () => {
  it('replaces the text of one block and leaves the array and its siblings intact', () => {
    const response = {
      content: [
        { type: 'text', text: 'keep' },
        { type: 'text', text: 'secret' },
      ],
    };
    expect(replaceResponseField(response, ['content', 1, 'text'], '[REDACTED]')).toEqual({
      content: [
        { type: 'text', text: 'keep' },
        { type: 'text', text: '[REDACTED]' },
      ],
    });
    expect(response.content[1]?.text).toBe('secret');
  });
});
