import { readFileSync } from 'node:fs';

import { scanText } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import {
  chunkRanges,
  collectResponseFields,
  replaceResponseField,
  RESPONSE_CHUNK_CHARS,
  RESPONSE_MAX_CAPTURES,
  RESPONSE_MAX_TOTAL_CHARS,
  scannableResponseFields,
  spliceResponseField,
} from '../../src/hooks/tool-response.ts';

// Grep tool_response objects as a live Claude Code sent them, one per output
// mode (see the file's own note for the host version).
const grepRecording = JSON.parse(
  readFileSync(new URL('../fixtures/grep-tool-response.json', import.meta.url), 'utf8'),
) as {
  hostVersion: string;
  calls: { tool_input: { output_mode: string }; tool_response: unknown }[];
};

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
  function recorded(mode: string, index = 0): unknown {
    const calls = grepRecording.calls.filter((c) => c.tool_input.output_mode === mode);
    const call = calls[index];
    if (!call) throw new Error(`no recorded ${mode} call`);
    return call.tool_response;
  }

  it('records an object response for every output mode, never a plain string', () => {
    expect(grepRecording.hostVersion).toMatch(/^\d+\.\d+\.\d+$/);
    expect(grepRecording.calls.map((c) => c.tool_input.output_mode).sort()).toEqual([
      'content',
      'content',
      'count',
      'files_with_matches',
    ]);
    for (const call of grepRecording.calls) {
      expect(typeof call.tool_response, call.tool_input.output_mode).toBe('object');
    }
  });

  it('scans the matching lines of a recorded content-mode response', () => {
    expect(scannableResponseFields('Grep', recorded('content'))).toEqual([
      { path: ['content'], text: 'src/a.txt:2:beta marker here\nsrc/b.txt:1:marker again' },
    ]);
  });

  it('scans the per-file counts of a recorded count-mode response', () => {
    expect(scannableResponseFields('Grep', recorded('count'))).toEqual([
      { path: ['content'], text: 'src/a.txt:1\nsrc/b.txt:1' },
    ]);
  });

  it('scans nothing for the recorded files_with_matches and no-match responses', () => {
    expect(scannableResponseFields('Grep', recorded('files_with_matches'))).toEqual([]);
    expect(scannableResponseFields('Grep', recorded('content', 1))).toEqual([]);
  });

  it('would scan a plain-string response whole, as for any tool', () => {
    expect(scannableResponseFields('Grep', 'No files found')).toEqual([
      { path: [], text: 'No files found' },
    ]);
  });

  it('chunks a content result longer than one chunk, line-aligned', () => {
    const line = `src/a.ts:1:${'z'.repeat(89)}\n`;
    const content = line.repeat(Math.ceil((RESPONSE_CHUNK_CHARS * 2.5) / line.length));
    const fields = scannableResponseFields('Grep', { mode: 'content', content });
    expect(fields.length).toBe(3);
    for (const field of fields) {
      expect(field.path).toEqual(['content']);
      expect(field.text.length).toBeLessThanOrEqual(RESPONSE_CHUNK_CHARS);
      expect(field.text.endsWith('\n')).toBe(true);
      expect(content.slice(field.range?.start, field.range?.end)).toBe(field.text);
    }
    expect(fields.map((f) => f.text).join('')).toBe(content);
  });

  it('scans a content result only up to the total character budget', () => {
    const line = `src/a.ts:1:${'z'.repeat(89)}\n`;
    const content = line.repeat(Math.ceil((RESPONSE_MAX_TOTAL_CHARS + 50_000) / line.length));
    const fields = scannableResponseFields('Grep', { mode: 'content', content });
    const total = fields.reduce((sum, field) => sum + field.text.length, 0);
    expect(total).toBe(RESPONSE_MAX_TOTAL_CHARS);
    expect(fields.at(-1)?.range?.end).toBe(RESPONSE_MAX_TOTAL_CHARS);
  });
});

describe('chunkRanges', () => {
  it('returns one range for text that fits', () => {
    expect(chunkRanges('short', 10)).toEqual([{ start: 0, end: 5 }]);
  });

  it('cuts after the last newline inside each chunk', () => {
    expect(chunkRanges('aaa\nbbb\nccccc', 6)).toEqual([
      { start: 0, end: 4 },
      { start: 4, end: 8 },
      { start: 8, end: 13 },
    ]);
  });

  it('hard-cuts a line longer than a chunk, never inside a surrogate pair', () => {
    expect(chunkRanges('abcdefgh', 3)).toEqual([
      { start: 0, end: 3 },
      { start: 3, end: 6 },
      { start: 6, end: 8 },
    ]);
    // Cutting at 3 would separate the pair at indices 2 and 3.
    expect(chunkRanges('ab\u{1F600}cd', 3)[0]).toEqual({ start: 0, end: 2 });
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

  it('caps the number of captures', () => {
    const response = Array.from({ length: RESPONSE_MAX_CAPTURES + 50 }, (_, i) => ({
      type: 'text',
      text: `block ${String(i)}`,
    }));
    const fields = scannableResponseFields(tool, response);
    expect(fields).toHaveLength(RESPONSE_MAX_CAPTURES);
    expect(fields.at(-1)?.path).toEqual([RESPONSE_MAX_CAPTURES - 1, 'text']);
  });

  it('chunks a block longer than one chunk and still scans its siblings', () => {
    const response = [
      { type: 'text', text: 'x'.repeat(RESPONSE_CHUNK_CHARS + 1) },
      { type: 'text', text: 'after the long block' },
    ];
    expect(scannableResponseFields(tool, response)).toEqual([
      {
        path: [0, 'text'],
        text: 'x'.repeat(RESPONSE_CHUNK_CHARS),
        range: { start: 0, end: RESPONSE_CHUNK_CHARS },
      },
      {
        path: [0, 'text'],
        text: 'x',
        range: { start: RESPONSE_CHUNK_CHARS, end: RESPONSE_CHUNK_CHARS + 1 },
      },
      { path: [1, 'text'], text: 'after the long block' },
    ]);
  });

  it('stops once the total character budget is spent', () => {
    const perBlock = RESPONSE_CHUNK_CHARS;
    const fitting = Math.floor(RESPONSE_MAX_TOTAL_CHARS / perBlock);
    const response = Array.from({ length: fitting + 2 }, () => ({
      type: 'text',
      text: 'y'.repeat(perBlock),
    }));
    const fields = scannableResponseFields(tool, response);
    expect(fields).toHaveLength(fitting);
    const total = fields.reduce((sum, field) => sum + field.text.length, 0);
    expect(total).toBeLessThanOrEqual(RESPONSE_MAX_TOTAL_CHARS);
  });

  it('applies the block walk only to the mcp__ prefix', () => {
    const response = [{ type: 'text', text: 'not an mcp tool' }];
    expect(scannableResponseFields('mcp_reader', response)).toEqual([]);
    expect(scannableResponseFields('Glob', response)).toEqual([]);
  });
});

describe('spliceResponseField', () => {
  it('splices chunk rewrites by their original ranges and keeps the rest', () => {
    const response = { mode: 'content', content: 'aaaa\nbbbb\ncccc\n' };
    const updated = spliceResponseField(
      response,
      ['content'],
      [
        { start: 10, end: 15, text: '[withheld]\n' },
        { start: 0, end: 5, text: 'A\n' },
      ],
    );
    expect(updated).toEqual({ mode: 'content', content: 'A\nbbbb\n[withheld]\n' });
    expect(response.content).toBe('aaaa\nbbbb\ncccc\n');
  });

  it('leaves the response alone when the path holds no string or a range overlaps', () => {
    const response = { content: 'abc' };
    expect(spliceResponseField(response, ['missing'], [{ start: 0, end: 1, text: 'x' }])).toBe(
      response,
    );
    expect(
      spliceResponseField(
        response,
        ['content'],
        [
          { start: 0, end: 2, text: 'x' },
          { start: 1, end: 3, text: 'y' },
        ],
      ),
    ).toBe(response);
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

describe('collectResponseFields — truncation', () => {
  it('is not truncated when every field fits, including a string of exactly the budget', () => {
    expect(collectResponseFields('Bash', { stdout: 'a', stderr: 'b' }).truncated).toBe(false);
    const exact = collectResponseFields('Bash', 'line\n'.repeat(RESPONSE_MAX_TOTAL_CHARS / 5));
    expect(exact.truncated).toBe(false);
    expect(exact.fields.at(-1)?.range?.end).toBe(RESPONSE_MAX_TOTAL_CHARS);
  });

  it('is truncated when the character budget cuts a string short', () => {
    const over = collectResponseFields('Bash', 'x'.repeat(RESPONSE_MAX_TOTAL_CHARS + 1));
    expect(over.truncated).toBe(true);
    expect(over.fields.reduce((sum, f) => sum + f.text.length, 0)).toBe(RESPONSE_MAX_TOTAL_CHARS);
  });

  it('is truncated when the budget is spent before a later field', () => {
    const stdout = 'line\n'.repeat(RESPONSE_MAX_TOTAL_CHARS / 5);
    const { fields, truncated } = collectResponseFields('Bash', { stdout, stderr: 'after' });
    expect(truncated).toBe(true);
    expect(fields.every((f) => f.path[0] === 'stdout')).toBe(true);
  });

  // The unit half of the e2e size-bound case in test/e2e/fail-open.e2e.test.ts: the
  // same stdout shape and lengths, so the hook's fail-open count there rests on
  // this fact rather than on the scan deadline, which a 5,000,050-character
  // response can also trip and would satisfy that assertion on its own.
  it('is truncated for the e2e 5,000,050-character Bash stdout and not for 4,999,000', () => {
    const line = `build step ${'q'.repeat(88)}\n`;
    const stdoutOf = (length: number): string => {
      const tail = 'last line\n';
      const fill = line.repeat(Math.ceil(length / line.length)).slice(0, length - tail.length);
      return fill + tail;
    };
    const response = (stdout: string): unknown => ({
      stdout,
      stderr: '',
      interrupted: false,
      isImage: false,
    });
    const over = stdoutOf(5_000_050);
    expect(over).toHaveLength(5_000_050);
    expect(collectResponseFields('Bash', response(over)).truncated).toBe(true);
    expect(collectResponseFields('Bash', response(stdoutOf(4_999_000))).truncated).toBe(false);
  });

  it('is truncated past the capture cap and not at it', () => {
    const blocks = (n: number) => Array.from({ length: n }, () => ({ type: 'text', text: 'x' }));
    expect(collectResponseFields('mcp__s__t', blocks(RESPONSE_MAX_CAPTURES)).truncated).toBe(false);
    const over = collectResponseFields('mcp__s__t', blocks(RESPONSE_MAX_CAPTURES + 1));
    expect(over.truncated).toBe(true);
    expect(over.fields).toHaveLength(RESPONSE_MAX_CAPTURES);
  });

  it('is truncated when the capture cap stops a chunked block partway', () => {
    const blocks = [
      ...Array.from({ length: RESPONSE_MAX_CAPTURES - 1 }, () => ({ type: 'text', text: 'x' })),
      { type: 'text', text: 'y'.repeat(RESPONSE_CHUNK_CHARS * 2) },
    ];
    const { fields, truncated } = collectResponseFields('mcp__s__t', blocks);
    expect(truncated).toBe(true);
    expect(fields).toHaveLength(RESPONSE_MAX_CAPTURES);
  });
});

describe('a requiresNearby label on the far side of a chunk cut', () => {
  // A documented limit (see the chunking comment in tool-response.ts): a label
  // is looked for only inside the chunk its value sits in. core-pii/dob needs
  // a nearby label such as "dob" within 160 characters of the date.
  const line = `${'q'.repeat(99)}\n`;
  const pad = `${'q'.repeat(94)}\n`;
  const dobFindings = (stdout: string): number =>
    scannableResponseFields('Bash', { stdout })
      .flatMap((field) => scanText(field.text).findings)
      .filter((finding) => finding.ruleId === 'core-pii/dob').length;

  it('does not corroborate a value whose label ends the previous chunk', () => {
    const head = line.repeat(1_999) + pad + 'dob:\n';
    expect(head).toHaveLength(RESPONSE_CHUNK_CHARS);
    const text = `${head}1990-05-04\n${line.repeat(1_999)}`;
    expect(chunkRanges(text, RESPONSE_CHUNK_CHARS)[0]?.end).toBe(RESPONSE_CHUNK_CHARS);
    expect(dobFindings(text)).toBe(0);
  });

  it('corroborates the same pair one line earlier, inside one chunk', () => {
    const text = `${line.repeat(1_998)}${pad}dob:\n1990-05-04\n${line.repeat(2_000)}`;
    expect(dobFindings(text)).toBe(1);
  });
});
