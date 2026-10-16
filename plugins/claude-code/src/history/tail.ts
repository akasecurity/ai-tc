// Incremental per-session transcript tail reader for the live Stop-hook reconcile.
// A whole-file re-read on every turn would be wasteful and (more
// importantly for the partial/final split) re-parse already-consumed records; the
// tail reader instead consumes ONLY the bytes appended since the last pass, tracked
// by a per-session byte offset persisted beside the transcript marker.
//
// Two correctness rules baked in here:
//   1. NEVER consume a half-written final line. We read from the stored offset to
//      EOF but cut at the LAST NEWLINE — the bytes after it are an in-flight record
//      that Claude Code is still writing; the rest arrives next pass. The advanced
//      offset therefore points exactly at the byte after the last complete line.
//   2. Handle truncation/rotation: if the file is now SMALLER than the stored
//      offset, the session file was replaced — reset to 0 and re-read from the top.
//      The UPSERT-take-MAX / INSERT-OR-IGNORE writes make the re-read a safe no-op.
//
// The offset marker also carries `lastPromptId`, the run_key carry-forward across
// tail boundaries: a tool-result-only tail whose parent prompt
// was consumed in a prior pass still attributes its run_key from this seed.
//
// It also carries what account attribution needs across passes: where the next
// pass resumes the session's observation log, the time of that log's first line
// (which names the log the offset indexes), the attribution state carried past
// this tail, and how many passes have waited at this offset for a record's
// closing observation.
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
import type {
  AttributionCarry,
  AttributionView,
  PendingHold,
} from '@akasecurity/plugin-sdk/account';

// Per-session reconcile checkpoint, persisted as JSON at
// `<dataDir>/usage-offsets/<sessionId>`. `offset` is the byte position one past the
// last COMPLETE line consumed; `lastPromptId` seeds the next pass's run_key.
export interface UsageOffset {
  offset: number;
  // `?: string | undefined` (not just `?: string`): callers thread the carried
  // promptId straight through (it's `string | undefined`), and under
  // `exactOptionalPropertyTypes` a present-but-undefined value needs the union.
  // `writeOffset` still omits the key entirely when it's undefined.
  lastPromptId?: string | undefined;
  // Where the next pass resumes the session's observation log, the time of the
  // first line of the log that offset indexes, and the attribution state carried
  // past this tail. Read back only past offset 0: a pass from offset 0 reads the
  // log from its start. A log offset above 0 with no time names no log.
  logOffset?: number | undefined;
  logStartedAt?: number | undefined;
  carried?: AttributionCarry | undefined;
  // How many passes have waited at this offset for a record's closing
  // observation, and when the first of them did.
  pending?: PendingHold | undefined;
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
// absorb. A non-finite/negative stored offset is also normalized to 0. An account
// field that does not read as its shape is dropped alone.
export function readOffset(dataDir: string, sessionId: string): UsageOffset {
  try {
    const raw = readFileSync(offsetPath(dataDir, sessionId), 'utf8');
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed === 'object' && parsed !== null) {
      const rec = parsed as Record<string, unknown>;
      const offset = isCount(rec.offset) ? rec.offset : 0;
      const lastPromptId = typeof rec.lastPromptId === 'string' ? rec.lastPromptId : undefined;
      const carried = offset > 0 ? carriedOf(rec.carried) : undefined;
      const pending = pendingOf(rec.pending);
      return {
        offset,
        ...(lastPromptId !== undefined ? { lastPromptId } : {}),
        ...(offset > 0 && isCount(rec.logOffset) ? { logOffset: rec.logOffset } : {}),
        ...(offset > 0 && isCount(rec.logStartedAt) ? { logStartedAt: rec.logStartedAt } : {}),
        ...(carried !== undefined ? { carried } : {}),
        ...(pending !== undefined ? { pending } : {}),
      };
    }
  } catch {
    // No marker yet, or unreadable/corrupt → start from the top.
  }
  return { offset: 0 };
}

// Persist a session's checkpoint (best-effort; a write failure just means the next
// pass re-reads from the prior offset — idempotent, never lost). The payload is
// rebuilt from the fields this module knows, each spelled out, so a field a
// caller spreads in never reaches the file.
export function writeOffset(dataDir: string, sessionId: string, value: UsageOffset): void {
  try {
    mkdirSync(offsetsDir(dataDir), { recursive: true, mode: DATA_DIR_MODE });
    const payload: UsageOffset = {
      offset: value.offset,
      ...(value.lastPromptId !== undefined ? { lastPromptId: value.lastPromptId } : {}),
      ...(value.logOffset !== undefined ? { logOffset: value.logOffset } : {}),
      ...(value.logStartedAt !== undefined ? { logStartedAt: value.logStartedAt } : {}),
      ...(value.carried !== undefined ? { carried: carriedPayload(value.carried) } : {}),
      ...(value.pending !== undefined
        ? { pending: { passes: value.pending.passes, since: value.pending.since } }
        : {}),
    };
    writeFileSync(offsetPath(dataDir, sessionId), JSON.stringify(payload), {
      mode: DATA_FILE_MODE,
    });
  } catch {
    // Best-effort: an unwritable marker just re-reads the same tail next pass.
  }
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

// A carried attribution state as stored, or undefined when any of its fields
// does not read as its shape: a carry this build cannot trust is dropped whole.
function carriedOf(value: unknown): AttributionCarry | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const carried = value as Record<string, unknown>;
  if (typeof carried.inherited !== 'boolean') return undefined;
  const positions = ['anchorAt', 'changedAt', 'lastOrgAt', 'boundaryAt'] as const;
  if (positions.some((name) => carried[name] !== undefined && !isCount(carried[name]))) {
    return undefined;
  }
  const lastObs = carried.lastObs === undefined ? undefined : viewOf(carried.lastObs);
  if (carried.lastObs !== undefined && lastObs === undefined) return undefined;
  return {
    inherited: carried.inherited,
    ...(isCount(carried.anchorAt) ? { anchorAt: carried.anchorAt } : {}),
    ...(isCount(carried.changedAt) ? { changedAt: carried.changedAt } : {}),
    ...(isCount(carried.lastOrgAt) ? { lastOrgAt: carried.lastOrgAt } : {}),
    ...(isCount(carried.boundaryAt) ? { boundaryAt: carried.boundaryAt } : {}),
    ...(lastObs === undefined ? {} : { lastObs }),
  };
}

function viewOf(value: unknown): AttributionView | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const { t, k, h } = value as Record<string, unknown>;
  if (!isCount(t) || (k !== 'w' && k !== 'n' && k !== 'v')) return undefined;
  if (h !== undefined && typeof h !== 'string') return undefined;
  return { t, k, ...(h === undefined ? {} : { h }) };
}

function carriedPayload(carried: AttributionCarry): AttributionCarry {
  return {
    inherited: carried.inherited,
    ...(carried.anchorAt !== undefined ? { anchorAt: carried.anchorAt } : {}),
    ...(carried.changedAt !== undefined ? { changedAt: carried.changedAt } : {}),
    ...(carried.lastOrgAt !== undefined ? { lastOrgAt: carried.lastOrgAt } : {}),
    ...(carried.boundaryAt !== undefined ? { boundaryAt: carried.boundaryAt } : {}),
    ...(carried.lastObs !== undefined
      ? {
          lastObs: {
            t: carried.lastObs.t,
            k: carried.lastObs.k,
            ...(carried.lastObs.h !== undefined ? { h: carried.lastObs.h } : {}),
          },
        }
      : {}),
  };
}

function pendingOf(value: unknown): UsageOffset['pending'] {
  if (typeof value !== 'object' || value === null) return undefined;
  const pending = value as Record<string, unknown>;
  return isCount(pending.passes) && isCount(pending.since)
    ? { passes: pending.passes, since: pending.since }
    : undefined;
}

// Result of reading a transcript's new tail.
export interface TailRead {
  // The newly-consumed chunk (complete lines only). Empty when nothing new — or only
  // a half-written final line — is available.
  chunk: string;
  // The byte offset one past the last COMPLETE line — persist this as the next start.
  nextOffset: number;
  // Where the chunk starts: the stored offset, or 0 when the file shrank below it.
  from: number;
}

// Read the new tail of `transcriptPath` starting at `startOffset`, consuming up to
// (and including) the LAST NEWLINE only. Returns the consumed chunk and the advanced
// offset. Handles truncation/rotation by resetting to 0 when the file shrank below
// the stored offset. Fully fail-open: an unreadable/missing file yields an empty
// chunk and the unchanged offset (nothing consumed), so the next pass retries.
//
// Positioned reads on an open fd, never a whole-file read: a long session's
// transcript keeps growing, and the reconcile worker only ever needs the bytes
// after the stored offset, so per-pass memory is proportional to the NEW tail
// (the full file is read only after a rotation reset the offset to 0). Sizing
// from fstat on the same fd also keeps the size and the reads on one file even
// if the path is swapped between them.
export function readTail(transcriptPath: string, startOffset: number): TailRead {
  let fd: number;
  try {
    fd = openSync(transcriptPath, 'r');
  } catch {
    return { chunk: '', nextOffset: startOffset, from: startOffset };
  }
  try {
    const size = fstatSync(fd).size;

    // Truncated/rotated: the file is smaller than where we left off → re-read from 0.
    // Idempotent writes (UPSERT-max / INSERT OR IGNORE) make the re-read a no-op.
    const from = size < startOffset ? 0 : startOffset;
    if (from >= size) return { chunk: '', nextOffset: from, from }; // nothing new

    // Read ONLY the appended bytes, looping because a positioned read may
    // return short. A zero-byte read before the expected end (file shrank
    // mid-pass) just means we work with what arrived — the newline cut below
    // still guarantees only complete lines are consumed.
    const length = size - from;
    const buf = Buffer.allocUnsafe(length);
    let filled = 0;
    while (filled < length) {
      const bytesRead = readSync(fd, buf, filled, length - filled, from + filled);
      if (bytesRead === 0) break;
      filled += bytesRead;
    }

    // Cut at the last newline so a half-written final line is left for the
    // next pass. `lastIndexOf` is byte-accurate (\n is 0x0A, never a UTF-8
    // continuation byte), so the offset math stays exact for multibyte
    // content. No newline in the slice → only an incomplete line so far;
    // consume none.
    const slice = buf.subarray(0, filled);
    const lastNl = slice.lastIndexOf(0x0a);
    if (lastNl === -1) return { chunk: '', nextOffset: from, from };

    const consumedBytes = lastNl + 1; // include the newline
    const chunk = slice.subarray(0, consumedBytes).toString('utf8');
    return { chunk, nextOffset: from + consumedBytes, from };
  } catch {
    return { chunk: '', nextOffset: startOffset, from: startOffset };
  } finally {
    try {
      closeSync(fd);
    } catch {
      // fd already invalid — nothing to release.
    }
  }
}
