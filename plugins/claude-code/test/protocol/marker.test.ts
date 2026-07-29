// The per-session authenticity marker: stable within a session, replaced on a
// new session, always 16 lowercase hex, fail-open on fs faults, and never
// persisted anywhere but its single owner-only file (in particular: never the
// SQLite store).
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { sessionProtocolMarker } from '../../src/protocol/marker.ts';

const MARKER_SHAPE = /^[0-9a-f]{16}$/;

describe('sessionProtocolMarker', () => {
  const dirs: string[] = [];

  function tempDataDir(): string {
    const dir = mkdtempSync(join(tmpdir(), 'aka-marker-test-'));
    dirs.push(dir);
    return dir;
  }

  afterEach(() => {
    while (dirs.length > 0) {
      const dir = dirs.pop();
      if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
    }
  });

  it('is 16 lowercase hex characters', () => {
    const marker = sessionProtocolMarker(tempDataDir(), 'session-a');
    expect(marker).toMatch(MARKER_SHAPE);
  });

  it('returns the same marker for repeated calls in the same session', () => {
    const dataDir = tempDataDir();
    const first = sessionProtocolMarker(dataDir, 'session-a');
    const second = sessionProtocolMarker(dataDir, 'session-a');
    const third = sessionProtocolMarker(dataDir, 'session-a');
    expect(second).toBe(first);
    expect(third).toBe(first);
  });

  it('mints a new marker for a new session and overwrites the single file', () => {
    const dataDir = tempDataDir();
    const first = sessionProtocolMarker(dataDir, 'session-a');
    const second = sessionProtocolMarker(dataDir, 'session-b');
    expect(second).toMatch(MARKER_SHAPE);
    expect(second).not.toBe(first);

    // One file, overwritten — it now names session-b and second's marker, and
    // session-a's marker is gone from disk entirely.
    const stored = JSON.parse(readFileSync(join(dataDir, 'protocol-marker'), 'utf8')) as {
      sessionId: string;
      marker: string;
    };
    expect(stored.sessionId).toBe('session-b');
    expect(stored.marker).toBe(second);

    // And a later call for session-b reads that same marker back.
    expect(sessionProtocolMarker(dataDir, 'session-b')).toBe(second);
  });

  it('returns a fresh in-memory marker when no session id is available', () => {
    const dataDir = tempDataDir();
    const marker = sessionProtocolMarker(dataDir, undefined);
    expect(marker).toMatch(MARKER_SHAPE);
    // Nothing to key the file on → nothing persisted.
    expect(existsSync(join(dataDir, 'protocol-marker'))).toBe(false);
  });

  it('fails open when the data dir path is a file (fs error)', () => {
    const parent = tempDataDir();
    const notADir = join(parent, 'data');
    writeFileSync(notADir, 'this is a file, not a directory');
    const marker = sessionProtocolMarker(notADir, 'session-a');
    expect(marker).toMatch(MARKER_SHAPE);
  });

  it('never touches the SQLite store — no aka.db is created', () => {
    const dataDir = tempDataDir();
    sessionProtocolMarker(dataDir, 'session-a');
    sessionProtocolMarker(dataDir, 'session-b');
    expect(existsSync(join(dataDir, 'aka.db'))).toBe(false);
    // The marker file is the ONLY thing written.
    expect(readdirSync(dataDir)).toEqual(['protocol-marker']);
  });
});
