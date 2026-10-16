import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { UsageOffset } from '../../src/history/tail.ts';
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

describe('readOffset / writeOffset — the account fields', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-offset-account-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const lastObs = { t: 7, k: 'w', h: 'b'.repeat(64) } as const;
  const carried = {
    anchorAt: 10,
    changedAt: 40,
    lastOrgAt: 40,
    boundaryAt: 5,
    inherited: true,
    lastObs,
  };

  it('round-trips every account field', () => {
    const value: UsageOffset = {
      offset: 64,
      lastPromptId: 'p1',
      logOffset: 120,
      logStartedAt: 1_700_000_000_000,
      carried,
      pending: { passes: 2, since: 99 },
    };
    writeOffset(dir, 'sess-a', value);
    expect(readOffset(dir, 'sess-a')).toEqual(value);
  });

  it('round-trips the time a held pass has its follow-up due', () => {
    const value: UsageOffset = { offset: 0, pending: { passes: 2, since: 99, followUpAt: 4_000 } };
    writeOffset(dir, 'sess-f', value);
    expect(readOffset(dir, 'sess-f')).toEqual(value);
  });

  it.each([
    ['is negative', -1],
    ['is not a number', 'x'],
    ['is null', null],
  ])('drops a follow-up time that %s and keeps the hold', (_label, followUpAt) => {
    mkdirSync(join(dir, 'usage-offsets'), { recursive: true });
    writeFileSync(
      join(dir, 'usage-offsets', 'sess-j'),
      JSON.stringify({ offset: 0, pending: { passes: 1, since: 99, followUpAt } }),
    );
    expect(readOffset(dir, 'sess-j')).toEqual({ offset: 0, pending: { passes: 1, since: 99 } });
  });

  it('omits the follow-up time from the file when the hold has none', () => {
    writeOffset(dir, 'sess-k', { offset: 0, pending: { passes: 1, since: 99 } });
    expect(JSON.parse(readFileSync(join(dir, 'usage-offsets', 'sess-k'), 'utf8'))).toEqual({
      offset: 0,
      pending: { passes: 1, since: 99 },
    });
  });

  it('round-trips a carried state that names no boundary, anchor, change or last view', () => {
    const value: UsageOffset = { offset: 64, carried: { inherited: false } };
    writeOffset(dir, 'sess-b', value);
    expect(readOffset(dir, 'sess-b')).toEqual(value);
  });

  it('reads the log offset, the log time and the carried state back only past offset 0', () => {
    writeOffset(dir, 'sess-c', {
      offset: 0,
      logOffset: 120,
      logStartedAt: 1_700_000_000_000,
      carried,
      pending: { passes: 1, since: 99 },
    });
    expect(readOffset(dir, 'sess-c')).toEqual({ offset: 0, pending: { passes: 1, since: 99 } });
  });

  it('drops an account field it cannot read and keeps the rest', () => {
    mkdirSync(join(dir, 'usage-offsets'), { recursive: true });
    writeFileSync(
      join(dir, 'usage-offsets', 'sess-d'),
      JSON.stringify({
        offset: 9,
        logOffset: -1,
        logStartedAt: 'x',
        carried: { boundaryAt: 'x', inherited: true },
        pending: { passes: 1 },
      }),
    );
    expect(readOffset(dir, 'sess-d')).toEqual({ offset: 9 });
  });

  it('reads a checkpoint that holds a log offset and no log time, without the log time', () => {
    mkdirSync(join(dir, 'usage-offsets'), { recursive: true });
    writeFileSync(
      join(dir, 'usage-offsets', 'sess-g'),
      JSON.stringify({ offset: 9, logOffset: 120, carried }),
    );
    expect(readOffset(dir, 'sess-g')).toEqual({ offset: 9, logOffset: 120, carried });
  });

  it.each([
    ['is negative', -1],
    ['is not a number', 'x'],
    ['is null', null],
  ])('drops a log time that %s and keeps the log offset', (_label, logStartedAt) => {
    mkdirSync(join(dir, 'usage-offsets'), { recursive: true });
    writeFileSync(
      join(dir, 'usage-offsets', 'sess-h'),
      JSON.stringify({ offset: 9, logOffset: 120, logStartedAt }),
    );
    expect(readOffset(dir, 'sess-h')).toEqual({ offset: 9, logOffset: 120 });
  });

  it('omits the log time from the file when there is none', () => {
    writeOffset(dir, 'sess-i', { offset: 9, logOffset: 120 });
    expect(JSON.parse(readFileSync(join(dir, 'usage-offsets', 'sess-i'), 'utf8'))).toEqual({
      offset: 9,
      logOffset: 120,
    });
  });

  it.each([
    ['is not an object', 'x'],
    ['does not say whether the session inherited', { boundaryAt: 5 }],
    ['has a last view that is not an object', { inherited: false, lastObs: 'x' }],
    ['has a last view with an unknown kind', { inherited: false, lastObs: { t: 1, k: 'z' } }],
    [
      'has a last view with a hash that is not text',
      { inherited: false, lastObs: { t: 1, k: 'w', h: 7 } },
    ],
  ])('drops a carried state that %s', (_label, carried) => {
    mkdirSync(join(dir, 'usage-offsets'), { recursive: true });
    writeFileSync(join(dir, 'usage-offsets', 'sess-f'), JSON.stringify({ offset: 9, carried }));
    expect(readOffset(dir, 'sess-f')).toEqual({ offset: 9 });
  });

  it('writes the fields it knows and no other', () => {
    const value = { offset: 3, stray: true } as UsageOffset;
    writeOffset(dir, 'sess-e', value);
    expect(JSON.parse(readFileSync(join(dir, 'usage-offsets', 'sess-e'), 'utf8'))).toEqual({
      offset: 3,
    });
  });
});

describe('readTail — where the chunk starts', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-tail-from-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('is the stored offset, or 0 once the file shrank below it', () => {
    const file = join(dir, 't.jsonl');
    writeFileSync(file, 'line-a\nline-b\n');
    const first = readTail(file, 0);
    appendFileSync(file, 'line-c\n');
    expect(readTail(file, first.nextOffset).from).toBe(first.nextOffset);
    writeFileSync(file, 'new\n');
    expect(readTail(file, first.nextOffset).from).toBe(0);
  });

  it('is the stored offset when the last line is not finished or the file is missing', () => {
    const file = join(dir, 't.jsonl');
    writeFileSync(file, 'line-a\nhalf-writ');
    expect(readTail(file, 7)).toEqual({ chunk: '', nextOffset: 7, from: 7 });
    expect(readTail(join(dir, 'missing.jsonl'), 7)).toEqual({ chunk: '', nextOffset: 7, from: 7 });
  });
});
