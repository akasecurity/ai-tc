// Adapted from plugins/claude-code/src/hooks/tool-response.test.ts. Only Bash
// is mapped in RESPONSE_TEXT_PATHS today (see tool-response.ts's module
// comment for why apply_patch has no entry), so the Read/WebFetch cases from
// the Claude Code original don't apply here.
import { describe, expect, it } from 'vitest';

import { replaceResponseField, scannableResponseFields } from '../../src/hooks/tool-response.ts';

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

  it('returns nothing for tools without a known response shape (apply_patch, MCP tools)', () => {
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
