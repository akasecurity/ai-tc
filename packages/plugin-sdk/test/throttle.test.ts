import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  PER_KEY_MARKER_RETAIN_MS,
  PER_KEY_PRUNE_BATCH,
  throttled,
  throttledPerKey,
} from '../src/throttle.ts';

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
    expect(throttled(dir, 'first-last-attempt', 30_000)).toBe(false);
    // A second job gates on its own marker — firing the first does not throttle it.
    expect(throttled(dir, 'reconcile-last-attempt', 30_000)).toBe(false);
    // …and each is now throttled on its own.
    expect(throttled(dir, 'first-last-attempt', 30_000)).toBe(true);
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

describe('throttledPerKey', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-throttle-key-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function backdate(name: string, ageMs: number): void {
    const at = new Date(Date.now() - ageMs);
    utimesSync(join(dir, name), at, at);
  }

  it('throttles each key on its own marker, named as before', () => {
    expect(throttledPerKey(dir, 'p', 'a', 30_000)).toBe(false);
    expect(throttledPerKey(dir, 'p', 'a', 30_000)).toBe(true);
    expect(throttledPerKey(dir, 'p', 'b', 30_000)).toBe(false);
    // The marker name is the one the per-session callers always wrote, so a
    // marker already on disk keeps throttling.
    expect(existsSync(join(dir, 'p-a'))).toBe(true);
    expect(throttled(dir, 'p-b', 30_000)).toBe(true);
  });

  it('removes same-prefix markers idle past the retention, and nothing else', () => {
    for (const name of ['p-old', 'p-recent', 'q-old', 'pold']) {
      writeFileSync(join(dir, name), '0');
    }
    backdate('p-old', PER_KEY_MARKER_RETAIN_MS + 60_000);
    backdate('p-recent', PER_KEY_MARKER_RETAIN_MS - 60_000);
    backdate('q-old', PER_KEY_MARKER_RETAIN_MS + 60_000);
    backdate('pold', PER_KEY_MARKER_RETAIN_MS + 60_000);
    mkdirSync(join(dir, 'p-dir'));
    backdate('p-dir', PER_KEY_MARKER_RETAIN_MS + 60_000);

    expect(throttledPerKey(dir, 'p', 'new', 30_000)).toBe(false);

    expect(readdirSync(dir).sort()).toEqual(['p-dir', 'p-new', 'p-recent', 'pold', 'q-old']);
  });

  it('does no pruning on a throttled call', () => {
    expect(throttledPerKey(dir, 'p', 'a', 30_000)).toBe(false);
    writeFileSync(join(dir, 'p-old'), '0');
    backdate('p-old', PER_KEY_MARKER_RETAIN_MS + 60_000);

    expect(throttledPerKey(dir, 'p', 'a', 30_000)).toBe(true);
    expect(existsSync(join(dir, 'p-old'))).toBe(true);
  });

  it('never prunes a marker that could still throttle, even with a window past the retention', () => {
    const window = PER_KEY_MARKER_RETAIN_MS * 2;
    writeFileSync(join(dir, 'p-other'), '0');
    backdate('p-other', PER_KEY_MARKER_RETAIN_MS + 60_000);

    expect(throttledPerKey(dir, 'p', 'new', window)).toBe(false);

    expect(existsSync(join(dir, 'p-other'))).toBe(true);
    expect(throttled(dir, 'p-other', window)).toBe(true);
  });

  it('removes a large backlog a bounded batch at a time', () => {
    const backlog = PER_KEY_PRUNE_BATCH + 10;
    for (let i = 0; i < backlog; i += 1) {
      writeFileSync(join(dir, `p-s${String(i)}`), '0');
      backdate(`p-s${String(i)}`, PER_KEY_MARKER_RETAIN_MS + 60_000);
    }

    throttledPerKey(dir, 'p', 'first', 30_000);
    const stale = (): number => readdirSync(dir).filter((n) => n.startsWith('p-s')).length;
    expect(stale()).toBe(10);

    throttledPerKey(dir, 'p', 'second', 30_000);
    expect(stale()).toBe(0);
  });

  it('fail-open: an unreadable data dir never throttles and never throws', () => {
    const notADir = join(dir, 'file');
    writeFileSync(notADir, '0');
    expect(() => throttledPerKey(join(notADir, 'nested'), 'p', 'a', 30_000)).not.toThrow();
    expect(throttledPerKey(join(notADir, 'nested'), 'p', 'a', 30_000)).toBe(false);
  });
});
