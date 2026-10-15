import { mkdirSync, readdirSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
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
