import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  MOD_ACTIVE_TTL_MS,
  MOD_SESSIONS_DIR,
  modSessionFileName,
  modSessionNote,
  promptRedactionLines,
  promptRedactionMode,
} from '../src/mod-host-mode.ts';

let dir: string;

function leave(sessionId: string, at: number, text = modSessionNote(sessionId, at)): void {
  mkdirSync(join(dir, MOD_SESSIONS_DIR), { recursive: true });
  writeFileSync(join(dir, MOD_SESSIONS_DIR, modSessionFileName(sessionId)), text);
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-mod-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('promptRedactionMode', () => {
  it('is in-place for a session whose mod left a fresh note', () => {
    leave('s1', 1_000);
    expect(promptRedactionMode(dir, 's1', 1_000 + 1_000)).toBe('in-place');
  });

  it('is block when no note exists', () => {
    expect(promptRedactionMode(dir, 's1', 1_000)).toBe('block');
  });

  it('ignores a stale note: mods disabled since the session last renewed it', () => {
    leave('s1', 1_000);
    expect(promptRedactionMode(dir, 's1', 1_000 + MOD_ACTIVE_TTL_MS)).toBe('block');
  });

  it('ignores another session note when a session is named', () => {
    leave('other', 1_000);
    expect(promptRedactionMode(dir, 's1', 2_000)).toBe('block');
    expect(promptRedactionMode(dir, undefined, 2_000)).toBe('in-place');
  });

  it('ignores a note dated in the future and notes that do not parse', () => {
    leave('s1', 9_000);
    leave('s2', 1_000, 'not json');
    leave('s3', 1_000, JSON.stringify({ v: 2, sessionId: 's3', at: 1_000 }));
    expect(promptRedactionMode(dir, 's1', 1_000)).toBe('block');
    expect(promptRedactionMode(dir, 's2', 2_000)).toBe('block');
    expect(promptRedactionMode(dir, 's3', 2_000)).toBe('block');
  });

  it('reads the exact note shape the mod writes', () => {
    leave('s1', 5, JSON.stringify({ v: 1, sessionId: 's1', at: 5 }));
    expect(promptRedactionMode(dir, 's1', 6)).toBe('in-place');
  });
});

describe('promptRedactionLines', () => {
  it('says nothing on a machine with no Claude Code', () => {
    leave('s1', 1_000);
    expect(promptRedactionLines(dir, false, 1_500)).toEqual([]);
  });

  it('names in-place redaction when the mod is running', () => {
    leave('s1', 1_000);
    expect(promptRedactionLines(dir, true, 1_500).join('\n')).toContain('redacted in place');
  });

  it('names blocking when it is not', () => {
    expect(promptRedactionLines(dir, true, 1_500).join('\n')).toContain(
      'blocked when they need redaction',
    );
  });
});
