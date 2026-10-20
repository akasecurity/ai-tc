import { mkdirSync, readdirSync, statSync, unlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { DATA_DIR_MODE, DATA_FILE_MODE } from './data-dir.ts';

/**
 * On-disk min-gap throttle, shared across hook processes. Each hook is its own
 * short-lived process, so an in-memory guard would never see a prior fire — the
 * gate has to live on disk. Returns `true` when a previous attempt landed within
 * `windowMs` (so the caller should SKIP), and otherwise records this attempt
 * (touching the marker's mtime) and returns `false` (proceed).
 *
 * `markerName` namespaces the gate so independent background jobs throttle
 * SEPARATELY — each passes its own name and gates on its own window, without one
 * starving the other. The marker is a sibling file in `dataDir`. A gate keyed
 * per session goes through `throttledPerKey` below instead.
 *
 * Best-effort and fail-open in BOTH directions: a stat error (no marker yet, or
 * unreadable) is treated as "not throttled" so a transient fs hiccup never
 * silences the job, and a failed marker write still allows the spawn — at worst
 * the window isn't enforced for one invocation, never a crash.
 */
export function throttled(dataDir: string, markerName: string, windowMs: number): boolean {
  const marker = join(dataDir, markerName);
  try {
    if (Date.now() - statSync(marker).mtimeMs < windowMs) return true;
  } catch {
    // No marker yet (or unreadable) → treat as not throttled.
  }
  try {
    mkdirSync(dataDir, { recursive: true, mode: DATA_DIR_MODE });
    writeFileSync(marker, String(Date.now()), { mode: DATA_FILE_MODE });
  } catch {
    // Couldn't record the attempt; allow the spawn anyway (fail-open).
  }
  return false;
}

/**
 * How long a per-key marker is kept after its last attempt. Far longer than any
 * throttle window, so pruning never removes a marker that could still throttle.
 */
export const PER_KEY_MARKER_RETAIN_MS = 24 * 60 * 60 * 1000;

/**
 * The most stale markers one call removes. Bounds the work a hook does on a
 * data dir that already holds a large backlog; later calls remove the rest.
 */
export const PER_KEY_PRUNE_BATCH = 256;

/**
 * `throttled`, gated per KEY rather than per job: the marker is
 * `${prefix}-${key}`, so each key (a session id, say) throttles independently.
 *
 * One marker per key accumulates a file per key for ever, so each recorded
 * attempt also removes up to `PER_KEY_PRUNE_BATCH` sibling markers carrying the
 * same prefix whose last attempt is older than `PER_KEY_MARKER_RETAIN_MS` (or
 * the window, if that is longer). A removed marker reads as "no attempt yet",
 * which is what an attempt that old already means to the throttle, so pruning
 * changes no decision. A throttled call does no pruning. Best-effort like the
 * rest: any fs error leaves the markers in place.
 *
 * `key` must already be safe as a filename; the caller sanitizes it.
 */
export function throttledPerKey(
  dataDir: string,
  prefix: string,
  key: string,
  windowMs: number,
  nowMs: number = Date.now(),
): boolean {
  const markerName = `${prefix}-${key}`;
  if (throttled(dataDir, markerName, windowMs)) return true;
  const olderThanMs = Math.max(windowMs, PER_KEY_MARKER_RETAIN_MS);
  pruneStaleMarkers(dataDir, `${prefix}-`, markerName, olderThanMs, nowMs);
  return false;
}

/**
 * How far ahead of the clock a marker's timestamp may read before `gatePerKey`
 * takes it for a waiting pass rather than for the time a pass started.
 */
const CLOCK_SLACK_MS = 2_000;

/**
 * What `gatePerKey` tells a caller to do with one request.
 *
 * - `run`: no pass has been started for the key in the last window; start one now.
 * - `trail`: a pass started inside the window; start one that waits until `dueAt`
 *   (epoch milliseconds, the end of that window) and then runs.
 * - `covered`: a trailing pass is already waiting for its due time; do nothing.
 */
export type PerKeyGate =
  | { readonly kind: 'run' }
  | { readonly kind: 'trail'; readonly dueAt: number }
  | { readonly kind: 'covered' };

/**
 * `throttledPerKey` for a job whose last request in a window must still run.
 *
 * A bare throttle runs the first request of a window and drops the rest, so the
 * request that arrives last, with nothing after it to run, is lost. This gate
 * answers such a request with a trailing pass due when the window closes, and
 * gives the one trailing pass to every request that arrives before it is due.
 *
 * The marker's time is the time of the key's latest pass, started or waiting: a
 * trailing pass is recorded by moving the marker to its due time, which lies in
 * the future until then. Both are read the way `throttledPerKey` reads the
 * marker, so a marker holding a waiting pass throttles for its whole window and
 * is not pruned, and the next window is counted from the pass that ended this
 * one. At most one pass starts per window, as with the bare throttle.
 *
 * A marker dated ahead of the clock by less than `CLOCK_SLACK_MS` is read as the
 * time a pass started, because a file's timestamp and the clock come from
 * different sources and the first can lead the second by a few milliseconds. One
 * that far ahead holds a waiting pass that is due within the slack, and is read as
 * a pass that started too, which at worst schedules one more trailing pass.
 *
 * The same fail-open rules hold: an unreadable marker or data dir answers `run`,
 * and a marker that cannot be moved still answers `trail`, so a request is never
 * dropped for a filesystem error; at worst a later request schedules another pass.
 */
export function gatePerKey(
  dataDir: string,
  prefix: string,
  key: string,
  windowMs: number,
  nowMs: number = Date.now(),
): PerKeyGate {
  if (!throttledPerKey(dataDir, prefix, key, windowMs, nowMs)) return { kind: 'run' };
  const marker = join(dataDir, `${prefix}-${key}`);
  let stampedAt: number;
  try {
    stampedAt = statSync(marker).mtimeMs;
  } catch {
    return { kind: 'run' };
  }
  if (stampedAt > nowMs + Math.min(CLOCK_SLACK_MS, windowMs / 2)) return { kind: 'covered' };
  const dueAt = Math.ceil(stampedAt + windowMs);
  try {
    utimesSync(marker, dueAt / 1000, dueAt / 1000);
  } catch {
    // The pass is not recorded; a later request schedules another.
  }
  return { kind: 'trail', dueAt };
}

function pruneStaleMarkers(
  dataDir: string,
  namePrefix: string,
  keep: string,
  olderThanMs: number,
  nowMs: number,
): void {
  let names: string[];
  try {
    names = readdirSync(dataDir);
  } catch {
    return;
  }
  let removed = 0;
  for (const name of names) {
    if (removed >= PER_KEY_PRUNE_BATCH) return;
    if (name === keep || !name.startsWith(namePrefix)) continue;
    const path = join(dataDir, name);
    try {
      const stat = statSync(path);
      if (!stat.isFile() || nowMs - stat.mtimeMs <= olderThanMs) continue;
      unlinkSync(path);
      removed += 1;
    } catch {
      // Gone already, or not removable — leave it for a later call.
    }
  }
}
