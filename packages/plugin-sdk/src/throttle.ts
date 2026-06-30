import { mkdirSync, statSync, writeFileSync } from 'node:fs';
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
 * SEPARATELY — e.g. the sync spawn (`sync-last-attempt`) and the token reconcile
 * spawn (`reconcile-last-attempt`) each gate on their own window without one
 * starving the other. The marker is a sibling file in `dataDir`.
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
