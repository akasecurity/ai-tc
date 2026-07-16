import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { readOffset, readTail, safeSessionId, writeOffset } from '../../src/history/tail.ts';

describe('readTail — incremental byte-offset tail read', () => {
  let dir: string;
  let file: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-tail-'));
    file = join(dir, 't.jsonl');
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('first pass consumes the whole file (up to the last newline) and records the offset', () => {
    const content = 'line-a\nline-b\n';
    writeFileSync(file, content);

    const { chunk, nextOffset } = readTail(file, 0);
    expect(chunk).toBe(content);
    expect(nextOffset).toBe(Buffer.byteLength(content));
  });

  it('a second pass consumes ONLY the newly-appended tail, not the earlier lines', () => {
    writeFileSync(file, 'line-a\nline-b\n');
    const first = readTail(file, 0);
    expect(first.chunk).toBe('line-a\nline-b\n');

    appendFileSync(file, 'line-c\nline-d\n');
    const second = readTail(file, first.nextOffset);
    // Only the new tail — the earlier lines are NOT re-read.
    expect(second.chunk).toBe('line-c\nline-d\n');
    expect(second.nextOffset).toBe(Buffer.byteLength('line-a\nline-b\nline-c\nline-d\n'));
  });

  it('does NOT consume a half-written final line until it is completed', () => {
    // A trailing line with no newline is still in-flight — leave it for next pass.
    writeFileSync(file, 'line-a\nhalf-writt');
    const first = readTail(file, 0);
    expect(first.chunk).toBe('line-a\n');
    expect(first.nextOffset).toBe(Buffer.byteLength('line-a\n'));

    // Complete the line — now it (and only it) is consumed from the recorded offset.
    appendFileSync(file, 'en-now\n');
    const second = readTail(file, first.nextOffset);
    expect(second.chunk).toBe('half-written-now\n');
  });

  it('returns an empty chunk when nothing new (or only an incomplete line) is present', () => {
    writeFileSync(file, 'line-a\n');
    const first = readTail(file, 0);
    // No further bytes → empty chunk, offset unchanged.
    const second = readTail(file, first.nextOffset);
    expect(second.chunk).toBe('');
    expect(second.nextOffset).toBe(first.nextOffset);
  });

  it('resets to 0 and re-reads when the file shrank (rotation/truncation)', () => {
    writeFileSync(file, 'old-a\nold-b\nold-c\n');
    const first = readTail(file, 0);
    expect(first.nextOffset).toBe(Buffer.byteLength('old-a\nold-b\nold-c\n'));

    // File replaced with a shorter one → stored offset now exceeds the size.
    writeFileSync(file, 'new-a\n');
    const after = readTail(file, first.nextOffset);
    expect(after.chunk).toBe('new-a\n'); // re-read from the top
    expect(after.nextOffset).toBe(Buffer.byteLength('new-a\n'));
  });

  it('fail-open: a missing file yields an empty chunk and the unchanged offset', () => {
    const { chunk, nextOffset } = readTail(join(dir, 'does-not-exist.jsonl'), 42);
    expect(chunk).toBe('');
    expect(nextOffset).toBe(42);
  });
});

describe('readOffset / writeOffset — per-session checkpoint', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-offset-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('a fresh session reads offset 0 and no seed', () => {
    expect(readOffset(dir, 'sess-new')).toEqual({ offset: 0 });
  });

  it('round-trips offset + lastPromptId', () => {
    writeOffset(dir, 'sess-1', { offset: 128, lastPromptId: 'p1' });
    expect(readOffset(dir, 'sess-1')).toEqual({ offset: 128, lastPromptId: 'p1' });
  });

  it('omits lastPromptId from the marker when undefined', () => {
    writeOffset(dir, 'sess-2', { offset: 64 });
    expect(readOffset(dir, 'sess-2')).toEqual({ offset: 64 });
  });

  it('fail-open: a corrupt marker reads as a fresh start (offset 0)', () => {
    mkdirSync(join(dir, 'usage-offsets'), { recursive: true });
    writeFileSync(join(dir, 'usage-offsets', 'sess-3'), 'not json');
    expect(readOffset(dir, 'sess-3')).toEqual({ offset: 0 });
  });

  it('normalizes a negative/non-finite stored offset to 0', () => {
    mkdirSync(join(dir, 'usage-offsets'), { recursive: true });
    writeFileSync(join(dir, 'usage-offsets', 'sess-4'), JSON.stringify({ offset: -5 }));
    expect(readOffset(dir, 'sess-4')).toEqual({ offset: 0 });
  });

  it('a path-traversal session id never writes outside the offsets dir and still round-trips', () => {
    // The session id comes off hook stdin — a separator-bearing id must not
    // become a path component that escapes usage-offsets/.
    const hostile = join('..', '..', 'escape-target');
    writeOffset(dir, hostile, { offset: 7 });

    expect(existsSync(join(dir, '..', 'escape-target'))).toBe(false);
    expect(existsSync(join(dir, '..', '..', 'escape-target'))).toBe(false);
    // The marker landed INSIDE the offsets dir, under the sanitized name…
    expect(readdirSync(join(dir, 'usage-offsets'))).toEqual([safeSessionId(hostile)]);
    // …and the same hostile id reads its own checkpoint back.
    expect(readOffset(dir, hostile)).toEqual({ offset: 7 });
  });
});

describe('safeSessionId — filesystem-safe session id', () => {
  it('passes a normal harness-style id through unchanged', () => {
    expect(safeSessionId('3f9c2d1e-8a4b-4c70-9e21-d5f0a6b7c8d9')).toBe(
      '3f9c2d1e-8a4b-4c70-9e21-d5f0a6b7c8d9',
    );
    expect(safeSessionId('sess_01.A-b')).toBe('sess_01.A-b');
  });

  it('replaces separator-bearing, dot-only, and empty ids with a stable hash', () => {
    for (const hostile of ['../../etc', 'a/b', 'a\\b', '.', '..', '', 'a b']) {
      const safe = safeSessionId(hostile);
      expect(safe).toMatch(/^[0-9a-f]{64}$/);
      // Deterministic: the same session converges on the same marker.
      expect(safeSessionId(hostile)).toBe(safe);
    }
  });
});
