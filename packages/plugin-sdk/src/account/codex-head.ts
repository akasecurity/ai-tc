import { closeSync, openSync, readSync } from 'node:fs';

// The first line Codex writes for each new thread, read with bounded positional
// reads. Only the session id, the originator, the model provider and the
// creating account's id are kept.

export const CODEX_HEAD_READ_BYTES = 64 * 1024;
export const CODEX_HEAD_MAX_BYTES = 1024 * 1024;

const NEWLINE = 0x0a;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface CodexHead {
  readonly sessionId: string | undefined;
  readonly originator: string | undefined;
  readonly modelProvider: string | undefined;
  /** The thread creator's account id, lower-cased, only when it is UUID-shaped. */
  readonly creatorAccountId: string | undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNotFound(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

const text = (value: unknown): string | undefined =>
  typeof value === 'string' ? value : undefined;

function parseHead(line: string): CodexHead | undefined {
  let record: unknown;
  try {
    record = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (!isRecord(record) || record.type !== 'session_meta' || !isRecord(record.payload))
    return undefined;
  const payload = record.payload;
  const creator = text(payload.creator_account_id)?.toLowerCase();
  return {
    sessionId: text(payload.session_id) ?? text(payload.id),
    originator: text(payload.originator),
    modelProvider: text(payload.model_provider),
    creatorAccountId: creator !== undefined && UUID.test(creator) ? creator : undefined,
  };
}

/**
 * A rollout's head, from 64 KiB positional reads up to the first newline.
 * 'pending' for a missing file or a first line still being written; undefined
 * with no newline within 1 MiB, or a first line that is not session_meta.
 */
export function readCodexHead(rolloutPath: string): CodexHead | 'pending' | undefined {
  let fd: number;
  try {
    fd = openSync(rolloutPath, 'r');
  } catch (error) {
    return isNotFound(error) ? 'pending' : undefined;
  }
  try {
    const parts: Buffer[] = [];
    let total = 0;
    for (;;) {
      const want = Math.min(CODEX_HEAD_READ_BYTES, CODEX_HEAD_MAX_BYTES - total);
      if (want <= 0) return undefined;
      const chunk = Buffer.allocUnsafe(want);
      const read = readSync(fd, chunk, 0, want, total);
      if (read === 0) return 'pending';
      const newline = chunk.subarray(0, read).indexOf(NEWLINE);
      if (newline !== -1) {
        parts.push(chunk.subarray(0, newline));
        return parseHead(Buffer.concat(parts).toString('utf8'));
      }
      parts.push(chunk.subarray(0, read));
      total += read;
    }
  } catch {
    return undefined;
  } finally {
    try {
      closeSync(fd);
    } catch {
      // already closed
    }
  }
}
