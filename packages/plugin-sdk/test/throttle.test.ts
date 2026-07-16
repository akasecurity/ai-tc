import { mkdtempSync, readFileSync, rmSync, statSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { throttled } from '../src/throttle.ts';

describe('throttled', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-throttle-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('first call is NOT throttled and records the marker; second call within the window IS', () => {
    // First fire: no marker yet → proceed (false) and write the marker.
    expect(throttled(dir, 'm', 30_000)).toBe(false);
    const after = readFileSync(join(dir, 'm'), 'utf8');
    expect(after).not.toBe('');

    // Second fire within the window → skip (true).
    expect(throttled(dir, 'm', 30_000)).toBe(true);
  });

  it('two triggers within the window → exactly one marker write (spawn-once)', () => {
    expect(throttled(dir, 'spawn', 30_000)).toBe(false);
    const firstMtime = statSync(join(dir, 'spawn')).mtimeMs;

    // The throttled second call must NOT touch the marker (so a real spawn-trigger
    // wired on top of it spawns exactly once per window).
    expect(throttled(dir, 'spawn', 30_000)).toBe(true);
    expect(statSync(join(dir, 'spawn')).mtimeMs).toBe(firstMtime);
  });

  it('a stale marker older than the window does NOT throttle (proceeds + refreshes)', () => {
    // Write a marker, then backdate its mtime well outside the window.
    throttled(dir, 'stale', 30_000);
    const past = new Date(Date.now() - 60_000);
    utimesSync(join(dir, 'stale'), past, past);
    // The gap now exceeds the window → not throttled, and the marker is refreshed.
    expect(throttled(dir, 'stale', 30_000)).toBe(false);
    // …so an immediate follow-up IS throttled again.
    expect(throttled(dir, 'stale', 30_000)).toBe(true);
  });

  it('independent marker names gate independently', () => {
    expect(throttled(dir, 'sync-last-attempt', 30_000)).toBe(false);
    // A different job (reconcile) gates on its own marker — not throttled by sync.
    expect(throttled(dir, 'reconcile-last-attempt', 30_000)).toBe(false);
    // …and each is now throttled on its own.
    expect(throttled(dir, 'sync-last-attempt', 30_000)).toBe(true);
    expect(throttled(dir, 'reconcile-last-attempt', 30_000)).toBe(true);
  });

  it('fail-open: an unwritable data dir never throttles and never throws', () => {
    // Point at a path under a regular FILE so mkdir/stat/write all fail — the
    // helper must swallow and return false (proceed) rather than throw.
    const notADir = join(dir, 'm'); // 'm' is a file after the first call
    throttled(dir, 'm', 30_000);
    expect(() => throttled(join(notADir, 'nested'), 'x', 30_000)).not.toThrow();
    expect(throttled(join(notADir, 'nested'), 'x', 30_000)).toBe(false);
  });
});
