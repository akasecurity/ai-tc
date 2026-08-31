import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  ATTACHED_HISTORY_SYNC_STATE_FILENAME,
  ensureDataDirSync,
  writeOwnerOnlyFileSync,
} from '@akasecurity/persistence';

/**
 * Where the background drain's progress is recorded, for `status` to render.
 *
 * ITS OWN FILE, and not `attached-state.json`: the circuit breaker rewrites that
 * one wholesale on every transition, so anything else stored there is destroyed
 * without a trace. Not `attached-sync-state.json` either — that belongs to the
 * policy pull, and two jobs sharing a file is the same problem one step later.
 */
export const HISTORY_SYNC_STATE_FILENAME = ATTACHED_HISTORY_SYNC_STATE_FILENAME;

/** Where the drain has got to. */
export type HistorySyncPhase = 'filling' | 'complete';

/**
 * How the last pass ended.
 *
 * A CLOSED ENUM, like the policy pull's outcome, and for the same reason: this
 * is the only thing the pass records about a failure. A request's message can
 * carry the URL, a header echo or a body fragment, and the way to be certain
 * none of it reaches a rendered status line is never to write it down.
 */
export type HistorySyncOutcome = 'ok' | 'unreachable' | 'refused' | 'interrupted';

const PHASES: ReadonlySet<string> = new Set<HistorySyncPhase>(['filling', 'complete']);
const OUTCOMES: ReadonlySet<string> = new Set<HistorySyncOutcome>([
  'ok',
  'unreachable',
  'refused',
  'interrupted',
]);

/**
 * The persisted form.
 *
 * Every field is a number or a member of a frozen enum. There is no free-form
 * string anywhere in it — no error text, no session id, no endpoint — so the
 * file is structurally incapable of carrying a fragment of anything recorded.
 */
export interface HistorySyncState {
  specVersion: number;
  phase: HistorySyncPhase;
  lastOutcome: HistorySyncOutcome;
  lastPassAtMs: number;
  sentTotal: number;
  pendingTotal: number;
  skippedTotal: number;
  startedAtMs: number | null;
  completedAtMs: number | null;
}

const SPEC_VERSION = 1;

export function historySyncStatePath(dataDir: string): string {
  return join(dataDir, HISTORY_SYNC_STATE_FILENAME);
}

/**
 * Record where the drain has got to. Best-effort.
 *
 * Written through `writeOwnerOnlyFileSync` (tmp + rename, 0600 from creation)
 * rather than a bare write: a reader must see the old file or the new one and
 * never a torn one, and a truncating write that is interrupted would leave a
 * shorter file that parses as smaller numbers — progress silently running
 * backwards. The AUTHORITATIVE progress is a count over the store either way;
 * this file only saves recomputing it.
 */
export function writeHistorySyncState(
  dataDir: string,
  state: Omit<HistorySyncState, 'specVersion'>,
): void {
  try {
    ensureDataDirSync(dataDir);
    const persisted: HistorySyncState = { specVersion: SPEC_VERSION, ...state };
    writeOwnerOnlyFileSync(historySyncStatePath(dataDir), `${JSON.stringify(persisted)}\n`);
  } catch {
    // Bookkeeping must never fail the drain that produced it.
  }
}

/**
 * The last recorded progress, or null when there is none or it cannot be read.
 *
 * Every field is validated rather than trusted: this file is rendered, so a
 * hand-edited or partially written one must produce silence, not a wrong
 * number. A state written by a newer build with an outcome this one does not
 * know fails the same way — status then says nothing rather than guessing.
 */
export function readHistorySyncState(dataDir: string): HistorySyncState | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(historySyncStatePath(dataDir), 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return null;
    const r = parsed as Record<string, unknown>;
    if (r.specVersion !== SPEC_VERSION) return null;
    if (typeof r.phase !== 'string' || !PHASES.has(r.phase)) return null;
    if (typeof r.lastOutcome !== 'string' || !OUTCOMES.has(r.lastOutcome)) return null;
    if (!isCount(r.lastPassAtMs)) return null;
    if (!isCount(r.sentTotal) || !isCount(r.pendingTotal) || !isCount(r.skippedTotal)) return null;
    if (!isNullableCount(r.startedAtMs) || !isNullableCount(r.completedAtMs)) return null;
    return {
      specVersion: SPEC_VERSION,
      phase: r.phase as HistorySyncPhase,
      lastOutcome: r.lastOutcome as HistorySyncOutcome,
      lastPassAtMs: r.lastPassAtMs,
      sentTotal: r.sentTotal,
      pendingTotal: r.pendingTotal,
      skippedTotal: r.skippedTotal,
      startedAtMs: r.startedAtMs,
      completedAtMs: r.completedAtMs,
    };
  } catch {
    return null;
  }
}

function isCount(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0;
}

function isNullableCount(v: unknown): v is number | null {
  return v === null || isCount(v);
}
