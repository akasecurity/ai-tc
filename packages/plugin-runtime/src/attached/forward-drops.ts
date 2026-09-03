import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  ATTACHED_FORWARD_DROPS_FILENAME,
  ensureDataDirSync,
  writeOwnerOnlyFileSync,
} from '@akasecurity/persistence';

/**
 * Where events the live forward gives up on are counted, for `status` to render.
 *
 * Two causes, and this file exists for the first: the BATCH BUDGET, which was
 * the one kind of drop this package could not see at all. Every other forward
 * failure ends in `ForwardPolicy.run`'s catch and moves the breaker's own file,
 * which is what lets `aka status` say the forward is unhealthy. A batch-deadline
 * drop returns BEFORE `run` is called, so nothing was written anywhere — and the
 * machine it happens on is precisely the one that looks healthiest: a
 * slow-but-answering plane produces no failures at all, so the breaker stays
 * closed, the policy line says "synced", and the tail of every batch past the
 * budget is discarded indefinitely with nothing to show for it. That is the
 * shape §5 forbids for a dropped rule ("the scan says what it dropped"),
 * reached on the forwarding path.
 *
 * The second is a chunk this file's own `forwardBatch` gives up on ONCE the
 * breaker opens mid-retry — that call DOES move the breaker's file, but the
 * events themselves still land nowhere else: they are neither delivered nor
 * (past that one call) reached by anything that would count them again. The
 * two are worth telling apart in a rewrite of the surface that renders this,
 * but not worth a second file for: both describe rows this pass will not
 * re-offer, both are equally "at least" (see the `lastDropAtMs` comment on
 * concurrency), and this counter has never claimed to explain WHY, only how
 * many.
 *
 * NOT `attached-state.json`, and not for tidiness: `forward-policy.ts` rewrites
 * that file WHOLESALE on every breaker transition, so a counter parked there is
 * destroyed by the next success — which, in the slow-plane case this exists to
 * expose, is the very next thing that happens. `sync-state.ts` refused the same
 * file for the same reason.
 */
// Defined in @akasecurity/persistence, which sits below both detach surfaces
// (`aka detach` and the dashboard's settings action) and owns the list they
// both clear. Re-exported under this package's own name so its consumers are
// unaffected by where the string lives.
export const FORWARD_DROPS_FILENAME = ATTACHED_FORWARD_DROPS_FILENAME;

/**
 * A COUNT and a clock, and nothing else.
 *
 * Deliberately not the ids, the session, or the payloads that were dropped.
 * Writes land locally first and the forward is a copy, so the events themselves
 * are already on disk in the store; writing them again here would be the at-rest
 * outbox this design does not have, and the argument `forward-policy.ts` makes
 * for keeping `lastFailure` an enum applies to every field of this file too.
 */
export interface ForwardDrops {
  /**
   * Events this pass gave up on and will not re-offer, since the last attach
   * — past the batch budget, or because the breaker opened mid-retry with
   * nothing left to isolate.
   */
  droppedForwards: number;
  /** When the most recent drop happened, epoch millis on the local clock. */
  lastDropAtMs: number;
}

export function forwardDropsPath(dataDir: string): string {
  return join(dataDir, FORWARD_DROPS_FILENAME);
}

/**
 * Add `count` events to the tally.
 *
 * READ-MODIFY-WRITE with no lock, and that is a known imprecision rather than an
 * oversight: two detached reconcile workers can interleave and lose an
 * increment, exactly as the breaker's own file can. The renderer says "at least"
 * for that reason. A lock would be the wrong trade here — this is bookkeeping
 * behind an already-committed local write, and it must never be the thing that
 * delays or fails a forward.
 *
 * NEVER THROWS. A drop that cannot be written down is still a drop, and the
 * caller is on a fail-open path.
 */
export function recordForwardDrops(dataDir: string, count: number, nowMs: number): void {
  if (count <= 0) return;
  try {
    ensureDataDirSync(dataDir);
    const previous = readForwardDrops(dataDir);
    const next: ForwardDrops = {
      droppedForwards: (previous?.droppedForwards ?? 0) + count,
      lastDropAtMs: nowMs,
    };
    writeOwnerOnlyFileSync(forwardDropsPath(dataDir), `${JSON.stringify(next)}\n`);
  } catch {
    // Best-effort bookkeeping; never fail a forward over it.
  }
}

/**
 * The tally, or `null` when there is none or it cannot be read.
 *
 * A success does NOT clear this, and that is the whole point. A successful
 * forward disproves `lastFailure` — it says the plane is reachable now — but it
 * says nothing about events already discarded, and clearing on success would
 * re-hide precisely the slow-but-healthy machine this file exists to surface.
 * `aka detach` clears it, because a re-attach to another deployment must not
 * inherit drops belonging to the last one.
 */
export function readForwardDrops(dataDir: string): ForwardDrops | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(forwardDropsPath(dataDir), 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return null;
    const record = parsed as { droppedForwards?: unknown; lastDropAtMs?: unknown };
    // Validated rather than trusted: these values are rendered, and a
    // hand-edited or truncated file must read as "nothing recorded" rather than
    // put an arbitrary value into the status block.
    if (typeof record.droppedForwards !== 'number' || !Number.isFinite(record.droppedForwards)) {
      return null;
    }
    if (record.droppedForwards <= 0) return null;
    if (typeof record.lastDropAtMs !== 'number' || !Number.isFinite(record.lastDropAtMs)) {
      return null;
    }
    return { droppedForwards: record.droppedForwards, lastDropAtMs: record.lastDropAtMs };
  } catch {
    return null;
  }
}
