import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  ATTACHED_LABEL_SYNC_FILENAME,
  ensureDataDirSync,
  writeOwnerOnlyFileSync,
} from '@akasecurity/persistence';

/**
 * Labels the label pass could never send, counted for `status` to render.
 *
 * A grant or dismissal the wire contract refuses (a field past its cap) is
 * stamped reported so it stops holding the head of the queue on every run, and
 * counted here so that stamp is not silent. A COUNT and a clock, like
 * forward-drops.ts, and a file of its own: that one's reader treats a record
 * with no event drops as empty, and these are not events.
 */
export interface UnsendableLabels {
  unsendable: number;
  lastAtMs: number;
}

function path(dataDir: string): string {
  return join(dataDir, ATTACHED_LABEL_SYNC_FILENAME);
}

/** Add `count` to the tally. Unlocked read-modify-write, so a floor. NEVER THROWS. */
export function recordUnsendableLabels(dataDir: string, count: number, nowMs: number): void {
  if (count <= 0) return;
  try {
    ensureDataDirSync(dataDir);
    const previous = readUnsendableLabels(dataDir);
    const next: UnsendableLabels = {
      unsendable: (previous?.unsendable ?? 0) + count,
      lastAtMs: nowMs,
    };
    writeOwnerOnlyFileSync(path(dataDir), `${JSON.stringify(next)}\n`);
  } catch {
    // Best-effort bookkeeping.
  }
}

/** The tally, or `null` when there is none or it cannot be read. */
export function readUnsendableLabels(dataDir: string): UnsendableLabels | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path(dataDir), 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return null;
    const record = parsed as { unsendable?: unknown; lastAtMs?: unknown };
    if (typeof record.unsendable !== 'number' || !Number.isFinite(record.unsendable)) return null;
    if (record.unsendable <= 0) return null;
    if (typeof record.lastAtMs !== 'number' || !Number.isFinite(record.lastAtMs)) return null;
    return { unsendable: record.unsendable, lastAtMs: record.lastAtMs };
  } catch {
    return null;
  }
}
