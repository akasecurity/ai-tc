// Incremental per-session transcript tail reader for the live Stop-hook reconcile.
// Identical to plugins/claude-code/src/history/tail.ts — purely a byte-offset
// fs reader with no knowledge of the transcript's own record format, so it
// needs no Antigravity-specific changes.
//
// A whole-file re-read on every turn would be wasteful and (more
// importantly for the partial/final split) re-parse already-consumed records; the
// tail reader instead consumes ONLY the bytes appended since the last pass, tracked
// by a per-session byte offset persisted beside the transcript marker.
//
// Two correctness rules baked in here:
//   1. NEVER consume a half-written final line. We read from the stored offset to
//      EOF but cut at the LAST NEWLINE — the bytes after it are an in-flight record
//      that Antigravity is still writing; the rest arrives next pass. The advanced
//      offset therefore points exactly at the byte after the last complete line.
//   2. Handle truncation/rotation: if the file is now SMALLER than the stored
//      offset, the session file was replaced — reset to 0 and re-read from the top.
//      The UPSERT-take-MAX / INSERT-OR-IGNORE writes make the re-read a safe no-op.
//
// The offset marker also carries `lastPromptId` (Antigravity: the last seen turn_id),
// the run_key carry-forward across tail boundaries: a tail whose parent
// context was consumed in a prior pass still attributes its run_key from this seed.
import { createHash } from 'node:crypto';
import {
  closeSync,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

import { DATA_DIR_MODE, DATA_FILE_MODE } from '@akasecurity/plugin-sdk';

// Per-session reconcile checkpoint, persisted as JSON at
// `<dataDir>/usage-offsets/<sessionId>`. `offset` is the byte position one past the
// last COMPLETE line consumed; `lastPromptId` seeds the next pass's run_key.
export interface UsageOffset {
  offset: number;
  lastPromptId?: string | undefined;
}

// The directory holding per-session offset markers.
function offsetsDir(dataDir: string): string {
  return join(dataDir, 'usage-offsets');
}

// Filename-safe characters only — no path separators, no expansion room for a
// hostile id to name anything outside its directory.
const SAFE_SESSION_ID = /^[A-Za-z0-9._-]+$/;

/**
 * Filesystem-safe form of a hook-supplied session id, for embedding in paths
 * under the data dir (offset markers, throttle markers). The id arrives on
 * hook stdin, so treat it as untrusted input even though the harness generates
 * it: an id that is not a plain filename token (or that names a directory
 * entry like `.`/`..`) is replaced by its SHA-256 hex — deterministic, so the
 * same session still converges on one marker, and never escapes the directory
 * it is joined into.
 */
export function safeSessionId(sessionId: string): string {
  if (SAFE_SESSION_ID.test(sessionId) && sessionId !== '.' && sessionId !== '..') {
    return sessionId;
  }
  return createHash('sha256').update(sessionId).digest('hex');
}

function offsetPath(dataDir: string, sessionId: string): string {
  return join(offsetsDir(dataDir), safeSessionId(sessionId));
}

// Read a session's persisted checkpoint. Fail-open: a missing/corrupt/unreadable
// marker is treated as a fresh start (offset 0, no seed) so a bad marker can never
// break reconcile — at worst it re-reads from the top, which the idempotent writes
// absorb. A non-finite/negative stored offset is also normalized to 0.
export function readOffset(dataDir: string, sessionId: string): UsageOffset {
  try {
    const raw = readFileSync(offsetPath(dataDir, sessionId), 'utf8');
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed === 'object' && parsed !== null) {
      const rec = parsed as Record<string, unknown>;
      const offset =
        typeof rec.offset === 'number' && Number.isFinite(rec.offset) && rec.offset >= 0
          ? rec.offset
          : 0;
      const lastPromptId = typeof rec.lastPromptId === 'string' ? rec.lastPromptId : undefined;
      return lastPromptId !== undefined ? { offset, lastPromptId } : { offset };
    }
  } catch {
    // No marker yet, or unreadable/corrupt → start from the top.
  }
  return { offset: 0 };
}

// Persist a session's checkpoint (best-effort; a write failure just means the next
// pass re-reads from the prior offset — idempotent, never lost).
export function writeOffset(dataDir: string, sessionId: string, value: UsageOffset): void {
  try {
    mkdirSync(offsetsDir(dataDir), { recursive: true, mode: DATA_DIR_MODE });
    const payload: UsageOffset =
      value.lastPromptId !== undefined
        ? { offset: value.offset, lastPromptId: value.lastPromptId }
        : { offset: value.offset };
    writeFileSync(offsetPath(dataDir, sessionId), JSON.stringify(payload), {
      mode: DATA_FILE_MODE,
    });
  } catch {
    // Best-effort: an unwritable marker just re-reads the same tail next pass.
  }
}

// Result of reading a transcript's new tail.
export interface TailRead {
  // The newly-consumed chunk (complete lines only). Empty when nothing new — or only
  // a half-written final line — is available.
  chunk: string;
  // The byte offset one past the last COMPLETE line — persist this as the next start.
  nextOffset: number;
}

// Read the new tail of `transcriptPath` starting at `startOffset`, consuming up to
// (and including) the LAST NEWLINE only. Returns the consumed chunk and the advanced
// offset. Handles truncation/rotation by resetting to 0 when the file shrank below
// the stored offset. Fully fail-open: an unreadable/missing file yields an empty
// chunk and the unchanged offset (nothing consumed), so the next pass retries.
export function readTail(transcriptPath: string, startOffset: number): TailRead {
  let fd: number;
  try {
    fd = openSync(transcriptPath, 'r');
  } catch {
    return { chunk: '', nextOffset: startOffset };
  }
  try {
    const size = fstatSync(fd).size;

    // Truncated/rotated: the file is smaller than where we left off → re-read from 0.
    const from = size < startOffset ? 0 : startOffset;
    if (from >= size) return { chunk: '', nextOffset: from }; // nothing new

    const length = size - from;
    const buf = Buffer.allocUnsafe(length);
    let filled = 0;
    while (filled < length) {
      const bytesRead = readSync(fd, buf, filled, length - filled, from + filled);
      if (bytesRead === 0) break;
      filled += bytesRead;
    }

    const slice = buf.subarray(0, filled);
    const lastNl = slice.lastIndexOf(0x0a);
    if (lastNl === -1) return { chunk: '', nextOffset: from };

    const consumedBytes = lastNl + 1; // include the newline
    const chunk = slice.subarray(0, consumedBytes).toString('utf8');
    return { chunk, nextOffset: from + consumedBytes };
  } catch {
    return { chunk: '', nextOffset: startOffset };
  } finally {
    try {
      closeSync(fd);
    } catch {
      // fd already invalid — nothing to release.
    }
  }
}
