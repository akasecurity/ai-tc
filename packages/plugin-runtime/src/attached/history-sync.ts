import { createHash } from 'node:crypto';
import { hostname } from 'node:os';

import type { HistorySyncCounts, LocalDatabase } from '@akasecurity/persistence';
import {
  openLocalDatabase,
  readControlPlaneCredentialFile,
  readWorkspaceSettings,
} from '@akasecurity/persistence';
import { createRemoteClient } from '@akasecurity/remote';
import type { RecordAuditEventRequest } from '@akasecurity/schema';
import type { IngestEvent } from '@akasecurity/schema';
import {
  AUDIT_EVENT_BATCH_MAX,
  INGEST_BATCH_MAX,
  isAttached,
  isHistorySyncConsentValid,
} from '@akasecurity/schema';

import { rebuildCapture } from './capture-rebuild.ts';
import { BREAKER_COOLDOWN_MS, readForwardHealth } from './forward-policy.ts';
import { rebuildAuditEvent } from './history-rebuild.ts';
import type { HistorySyncOutcome } from './history-state.ts';

/**
 * Longer than the transport's own 10s default, and longer than any hook budget.
 *
 * The detached child has latitude the decision path does not: nobody is waiting
 * on it, and a request that would be abandoned on a hook is worth waiting for
 * here. Passed explicitly because the client's default would otherwise fire
 * first and make this constant unreachable.
 */
export const HISTORY_REQUEST_TIMEOUT_MS = 15_000;

/**
 * How long one pass may run before checkpointing and exiting.
 *
 * Hitting it PAUSES the drain; it does not fail it. Everything not yet sent
 * stays pending and the next pass resumes from the ledger — the exact inverse of
 * the live forward path, which discards the remainder of a batch past its
 * deadline and keeps only a tally.
 */
export const HISTORY_PASS_BUDGET_MS = 120_000;

/** A claim whose holder has not checked in for this long is takeable. */
export const HISTORY_LEASE_STALE_MS = 60_000;

/** How often the holder says it is still alive. */
const HEARTBEAT_EVERY_MS = 10_000;

/**
 * Half the per-key budget the deployment enforces.
 *
 * The drain shares one credential with this machine's live forwarding, and it
 * must never be the reason a real forward is rate-limited. 300 requests a minute
 * is one every 200ms.
 */
const PACE_INTERVAL_MS = 200;

/** Attempts for a failure that might not repeat, before the pass gives up. */
const MAX_ATTEMPTS = 4;

const MAX_BACKOFF_MS = 60_000;

/** How many sessions and rows one page reads. Memory is O(page), never O(history). */
const SESSION_PAGE = 25;
const ROW_PAGE = 200;

/**
 * How long a capture is left to the live path before the outbox claims it.
 *
 * Not a correctness boundary — an undelivered capture is owed however new it is,
 * and a row sent twice is absorbed by the receiver's id-dedup because the wire
 * id is derived from the row's own tuple. This only keeps the drain off rows the
 * live forward is plausibly still in flight on, so the common case stays one
 * send. Comfortably longer than the decision-path budget the live send runs
 * under.
 */
const CAPTURE_GRACE_MS = 30_000;

/** Captures per request, taken from the wire shape's own bound (see BATCH_SIZE). */
const CAPTURE_BATCH_SIZE = INGEST_BATCH_MAX;

/**
 * The share of one pass the structural lane may spend before it yields.
 *
 * Most of it, because the pre-attach backlog is the finite half and finishing it
 * is what makes later passes cheap. The remainder is what stops the capture lane
 * being starved behind a backlog measured in days — see drain(). A structural
 * loop that empties the backlog early hands the rest over, so this costs nothing
 * on a machine that has caught up.
 */
const STRUCTURAL_BUDGET_SHARE = 0.7;

/**
 * How many events ride one request.
 *
 * The single largest lever on how long a backlog takes: this work is round-trip
 * bound, not bandwidth bound, so batching is the difference between days of
 * accumulated session time and minutes. Taken from the wire shape's own bound
 * rather than restated, so the two cannot drift.
 */
const BATCH_SIZE = AUDIT_EVENT_BATCH_MAX;

export interface HistorySyncResult {
  outcome: HistorySyncOutcome;
  /** Rows accepted in THIS pass. */
  sent: number;
  /** Rows this pass gave up on permanently. */
  skipped: number;
  /**
   * Whether any CAPTURE is still owed after this pass.
   *
   * Reported separately because `counts` cannot carry it: every statement behind
   * it filters to the structural lane, so a caller reading `counts.pending === 0`
   * as "nothing is owed" would say the drain had finished while thousands of
   * captures waited. Computed here, where the attachment boundary is known — the
   * caller has neither that number nor an open store.
   *
   * Unlike the structural backlog this is NOT a fixed set: it grows with every
   * live session that fails to forward, so it answers "owed right now" and is
   * expected to go back to true after reading false.
   */
  capturesPending: boolean;
  /**
   * The ledger's totals after the pass — the AUTHORITATIVE progress.
   *
   * Returned rather than left for the caller to re-read, because the caller
   * writes the state file after the store handle has closed, and a count taken
   * from a second open could disagree with the pass that produced it.
   */
  counts: HistorySyncCounts;
  atMs: number;
}

export interface RunHistorySyncDeps {
  base: string;
  settingsDir: string;
  dataDir: string;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
  passBudgetMs?: number;
  openStore?: (dataDir: string) => LocalDatabase;
  sendBatch?: (events: readonly RecordAuditEventRequest[]) => Promise<void>;
  /** Injected alongside sendBatch in tests; the capture lane's route. */
  sendCaptures?: (events: readonly IngestEvent[]) => Promise<{ settled: number }>;
}

/** sha256 of the endpoint. Nothing reads the address back; only sameness matters. */
export function endpointFingerprint(endpoint: string): string {
  return createHash('sha256').update(endpoint).digest('hex');
}

/**
 * One pass of the background drain: send what has not been sent, mark what has.
 *
 * NEVER THROWS. It runs detached with stdio ignored, so a rejection would be an
 * unhandled rejection nobody reads.
 *
 * Returns `null` for NO ATTEMPT MADE — not attached, no usable credential, no
 * grant, or the forward breaker is open. That is distinct from every recorded
 * outcome, each of which describes something a deployment did, and the caller
 * writes nothing for it: recording one would have status report a deployment
 * this machine never called, and would re-create a file a detach just removed.
 *
 * ADVANCE ONLY AFTER AN ACK. A row is stamped delivered after the request that
 * carried it was accepted, never before. A crash in between costs one re-send,
 * which the receiving side settles on the row id; the other order would lose the
 * row silently.
 */
export async function runHistorySync(deps: RunHistorySyncDeps): Promise<HistorySyncResult | null> {
  const now = deps.now ?? ((): number => Date.now());
  const sleep =
    deps.sleep ?? ((ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms)));
  const random = deps.random ?? Math.random;
  const budgetMs = deps.passBudgetMs ?? HISTORY_PASS_BUDGET_MS;

  let db: LocalDatabase | undefined;
  try {
    const settings = readWorkspaceSettings(deps.base);
    if (!isAttached(settings)) return null;
    const connection = settings.controlPlane;
    if (connection === undefined) return null;
    if (!isHistorySyncConsentValid(settings.historySyncConsent, connection.endpoint)) return null;

    // The WIDE read: the client below needs the key itself, and this runs in
    // the plugin's own process rather than anywhere a browser can see.
    const state = readControlPlaneCredentialFile(deps.settingsDir, connection);
    if (!state.usable) return null;

    // READ-ONLY. A long-running child must never write the breaker: its view of
    // plane health would overwrite the hook path's, and the hook path is the one
    // a user is waiting on.
    //
    // OPEN MEANS WITHIN THE COOLDOWN, which is the same test `run()` applies —
    // not merely "a stamp is present". The stamp is never cleared by elapsing,
    // and the half-open probe RE-STAMPS it before every attempt, clearing it
    // only on a forward that succeeds. Treating any stamp as open would hold the
    // drain off for the whole window in which the live path has resumed probing,
    // and on a flaky deployment each cooldown re-stamps — so the job that most
    // needs to make progress during a partial outage would be the one held off
    // indefinitely by a breaker refusing nothing.
    const nowMs = now();
    const openedAtMs = readForwardHealth(deps.dataDir, nowMs)?.openedAtMs ?? null;
    if (openedAtMs !== null && nowMs - openedAtMs < BREAKER_COOLDOWN_MS) return null;

    db = (deps.openStore ?? openLocalDatabase)(deps.dataDir);
    const ledger = db.historySync;

    // WHERE THE BACKLOG ENDS. Everything recorded from the attachment onwards is
    // the live forward path's to deliver, and it delivers it with the
    // deployment's own inventory ids substituted in. A drain that re-sent those
    // rows would duplicate every one of them for the life of the install and —
    // for a session root, whose re-post is an UPDATE rather than a no-op —
    // overwrite those resolved ids with nothing, degrading a join that was
    // already correct.
    const attachedAtMs = Date.parse(connection.attachedAt);
    if (!Number.isFinite(attachedAtMs)) return null;

    // A change of deployment invalidates every stamp: rows delivered to the
    // place this machine has left are undelivered as far as this one is
    // concerned. It also re-freezes the boundary, which is the only time that
    // moves — a re-attach to the same deployment must not widen it.
    const fingerprint = endpointFingerprint(connection.endpoint);
    const recorded = ledger.deployment();
    let backlogBefore: number;
    if (recorded.fingerprint !== fingerprint) {
      // A different deployment. Nothing sent to the last one counts here, so
      // the stamps go and a fresh boundary is frozen.
      ledger.rearmFor(fingerprint, attachedAtMs);
      backlogBefore = attachedAtMs;
    } else if (recorded.backlogBefore === undefined) {
      // The same deployment, with the boundary RELEASED — a detach happened and
      // this is a re-attach. The window between the two is one nothing
      // forwarded, so the boundary moves forward to take it in. The stamps stay:
      // the recipient has not changed, so what it already has, it still has.
      ledger.freezeBoundary(attachedAtMs);
      backlogBefore = attachedAtMs;
    } else {
      // The same deployment with a boundary still in force — a key ROTATION, or
      // simply another pass. Re-freezing here would widen the backlog back over
      // rows the live path delivered while the machine stayed attached.
      backlogBefore = recorded.backlogBefore;
    }

    const pid = process.pid;
    if (!ledger.claim(pid, hostname(), now(), HISTORY_LEASE_STALE_MS)) return null;

    // ONE client, two senders. The lanes differ only in the route they take and
    // the shape they carry; sharing the client keeps them on one connection,
    // one timeout and — the part that matters — one credential read. A second
    // `createRemoteClient` here would be a second place to get that wrong.
    const client =
      deps.sendBatch !== undefined && deps.sendCaptures !== undefined
        ? undefined
        : createRemoteClient({
            endpoint: connection.endpoint,
            apiKey: state.credential.apiKey,
            timeoutMs: HISTORY_REQUEST_TIMEOUT_MS,
          });

    const send =
      deps.sendBatch ??
      (async (events: readonly RecordAuditEventRequest[]): Promise<void> => {
        // THROWS rather than optional-chains. `client` is undefined only when
        // both senders were injected, in which case this closure is unreachable
        // — but `await client?.recordAuditEvents(...)` would resolve silently if
        // the construction condition above ever changed, and the caller reads a
        // resolved promise as "delivered" and stamps the rows synced. That is
        // silent data loss on the one path that must not have any. The capture
        // sender already fails safe (no ack ⇒ settled 0 ⇒ 'unreachable'); this
        // makes the pair symmetric on purpose rather than by accident.
        if (client === undefined) throw new Error('history sync: no transport');
        // The fallback to one request per event is OPT-IN, and this is the
        // caller it is correct for: `HISTORY_REQUEST_TIMEOUT_MS` is charged PER
        // REQUEST, so 50 sequential sends get 50 budgets and an older
        // deployment simply drains slower. The live forward is the caller it is
        // wrong for — it bounds the whole call — which is why the client raises
        // by default and each caller says which it is.
        await client.recordAuditEvents(events, { fallbackToSingleEvents: true });
      });

    const sendCaptures =
      deps.sendCaptures ??
      (async (events: readonly IngestEvent[]): Promise<{ settled: number }> => {
        // Symmetric with `send` above: unreachable when both senders were
        // injected, and loud rather than silent if that ever stops being true.
        if (client === undefined) throw new Error('history sync: no transport');
        const ack = await client.ingestEvents({ events: [...events] });
        // `accepted + duplicates` is delivery — the same rule the live forward
        // stamps on. A duplicate IS a delivery: the receiver recognising a
        // resend by its id is exactly the outcome a reproduced id is for.
        return { settled: ack.accepted + ack.duplicates };
      });

    try {
      return await drain({
        ledger,
        send,
        sendCaptures,
        now,
        sleep,
        random,
        budgetMs,
        pid,
        backlogBefore,
      });
    } finally {
      ledger.release(pid);
    }
  } catch {
    // Nothing to report to and nowhere to report it. The ledger is unchanged
    // for anything not acknowledged, so the next pass repeats this one's work.
    return null;
  } finally {
    try {
      db?.close();
    } catch {
      // A handle that will not close is about to be reclaimed by process exit.
    }
  }
}

interface DrainDeps {
  ledger: LocalDatabase['historySync'];
  send: (events: readonly RecordAuditEventRequest[]) => Promise<void>;
  /**
   * The CAPTURE lane's sender — a different route from `send`, never a variant
   * of it. Returns how many the deployment took, so the caller can tell "your
   * batch landed" from "the call returned". See drainCaptures.
   */
  sendCaptures: (events: readonly IngestEvent[]) => Promise<{ settled: number }>;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  random: () => number;
  budgetMs: number;
  pid: number;
  /** Rows at or after this instant belong to the live path, not to this drain. */
  backlogBefore: number;
}

/** Why one row's send stopped: the pass continues, skips it, or ends. */
type RowVerdict = 'sent' | 'skip' | 'unreachable' | 'refused';

async function drain(d: DrainDeps): Promise<HistorySyncResult> {
  const startedAt = d.now();
  const deadline = startedAt + d.budgetMs;
  // A RESERVED SLICE, not an ordering. Running captures after the structural
  // loop is right within a pass — a capture whose session root has not arrived is
  // a stub until it does — but that loop exits only when the whole backlog is
  // gone or the budget is spent, so "second" would mean "not until the entire
  // pre-attach history has drained". `askAboutHistory` advertises backlogs in
  // days; passes are capped at 120s and throttled to one per five minutes. So on
  // exactly the machines with the largest backlog, the half the user was newly
  // asked about — and the only half where declining means "dropped rather than
  // kept" — would wait weeks while fresh undelivered captures piled up behind it.
  //
  // Structural still goes first and still gets most of the pass. It just cannot
  // take all of it.
  const structuralDeadline = Math.min(deadline, startedAt + d.budgetMs * STRUCTURAL_BUDGET_SHARE);
  let sent = 0;
  let skipped = 0;
  let lastHeartbeat = startedAt;

  /**
   * Say the claim is still held, at most once per interval.
   *
   * Threaded down into the send paths rather than called only between batches:
   * one batch's worst case is four attempts at the request timeout plus the
   * backoff ladder, which is already past the stale window, and the row-by-row
   * isolation path multiplies that by the batch size. Checking in only after a
   * batch returned would let a second child take the claim from a drain that is
   * alive and mid-request — exactly the case the claim was written for.
   */
  const beat = (): void => {
    const at = d.now();
    if (at - lastHeartbeat < HEARTBEAT_EVERY_MS) return;
    d.ledger.heartbeat(d.pid, at);
    lastHeartbeat = at;
  };

  // The structural phase runs TWICE at most: once against its reserved slice, and
  // again against the full deadline if the capture lane finished early. See the
  // second call below for why.
  const drainStructural = async (until: number): Promise<HistorySyncOutcome> => {
    let stopped: HistorySyncOutcome = 'ok';
    outer: while (d.now() < until) {
      const sessions = d.ledger.pendingSessions(SESSION_PAGE, d.backlogBefore);
      if (sessions.length === 0) break;

      for (const sessionId of sessions) {
        // ROOT FIRST, one session at a time. The receiving side has real
        // self-referencing foreign keys and stubs no missing root, so a leaf that
        // overtakes its session is rejected — which is why this is sequential
        // rather than concurrent.
        const rows = d.ledger.pendingRows(sessionId, ROW_PAGE, d.backlogBefore);
        if (rows.length === 0) continue;

        // Rebuilt first, so a row that can never be expressed is counted and
        // dropped rather than poisoning a batch it happens to share.
        const ready: { id: string; event: RecordAuditEventRequest }[] = [];
        for (const row of rows) {
          const event = rebuildAuditEvent(row, d.ledger.inspectionsFor(row.id));
          if (event === undefined) {
            // A local defect, not an outage: this row will never be expressible,
            // so retrying it for ever would stall the drain behind it.
            d.ledger.markSkipped([row.id]);
            skipped += 1;
            continue;
          }
          ready.push({ id: row.id, event });
        }

        // BATCHED WITHIN ONE SESSION, never across two. The rows arrive root
        // first, so a batch that stayed inside a session cannot deliver a leaf
        // before the root it keys onto; one spanning sessions could.
        for (let i = 0; i < ready.length; i += BATCH_SIZE) {
          if (d.now() >= until) {
            stopped = 'interrupted';
            break outer;
          }
          const chunk = ready.slice(i, i + BATCH_SIZE);
          const result = await sendChunk(d, chunk, beat);
          sent += result.sent;
          skipped += result.skipped;
          if (result.stopped !== undefined) {
            // Everything not acknowledged stays pending, by doing nothing.
            stopped = result.stopped;
            break outer;
          }

          beat();
          await d.sleep(PACE_INTERVAL_MS);
        }
      }
    }
    return stopped;
  };

  let outcome = await drainStructural(structuralDeadline);

  // THE CAPTURE LANE, second and deliberately so. The structural rows are what
  // make a session legible on the receiving side — a capture whose session has
  // no root is stubbed rather than rejected, but it is a stub until the root
  // arrives, and draining captures first would leave a deployment full of them.
  // Both lanes settle through the same statement, so the order costs nothing
  // else.
  // A structural loop that stopped at its own slice has not run out of time, and
  // must not be reported as though it had: the pass continues here, and the final
  // check below re-reads the real deadline. Only a stop at the PASS deadline is
  // an interruption.
  if (outcome === 'interrupted' && d.now() < deadline) outcome = 'ok';

  if (outcome === 'ok') {
    const captures = await drainCaptures(d, deadline, beat);
    sent += captures.sent;
    skipped += captures.skipped;
    if (captures.stopped !== undefined) outcome = captures.stopped;
  }

  // THE SLICE HANDS BACK. Reserving a share for captures is only half of the
  // reciprocity the constant claims — the other half is that a pass whose capture
  // lane found nothing owed, which is the normal case on a machine whose live
  // forwarding works, must not return with a third of its budget unspent while
  // the structural backlog it was reserved from is still there. Without this,
  // exactly the machines the slice was not needed for pay ~43% longer to drain a
  // backlog measured in days.
  //
  // Guarded on `capturesPending` rather than run unconditionally: a capture lane
  // that STOPPED — refused, unreachable, or out of time — has left work owed, and
  // spending the remainder on the other lane would be the starvation this whole
  // arrangement exists to prevent, inverted.
  if (
    outcome === 'ok' &&
    d.now() < deadline &&
    d.ledger.pendingCaptureRows(1, d.backlogBefore, d.now() - CAPTURE_GRACE_MS).length === 0
  ) {
    outcome = await drainStructural(deadline);
  }

  if (outcome === 'ok' && d.now() >= deadline && d.ledger.counts(d.backlogBefore).pending > 0) {
    outcome = 'interrupted';
  }
  return {
    outcome,
    sent,
    skipped,
    // LIMIT 1 — this asks "is anything owed", never "how much", so it must not
    // pay for a count over the capture grain on every pass.
    capturesPending:
      d.ledger.pendingCaptureRows(1, d.backlogBefore, d.now() - CAPTURE_GRACE_MS).length > 0,
    counts: d.ledger.counts(d.backlogBefore),
    atMs: d.now(),
  };
}

interface ChunkResult {
  sent: number;
  skipped: number;
  /** Set when the pass must stop; everything else stays pending. */
  stopped?: HistorySyncOutcome;
}

/**
 * Drain the captures this machine still owes — the half of the outbox that
 * carries text.
 *
 * Flat and time-ordered, with no session grouping, because /v1/events stubs a
 * missing session root on the leaf's own id. The structural lane pages by
 * session only because its route stubs nothing and its foreign keys are real.
 *
 * NO `dedupe` FLAG on the batch, and that is load-bearing rather than an
 * omission. `dedupe: 'content-hash'` would reject any event whose hash the
 * tenant has already seen, and two genuinely separate prompts can be
 * byte-identical — a user asking "why?" twice is two events on the timeline.
 * Id-dedup always applies and is the one this lane needs: the id is reproduced
 * from the row's own tuple, so a redelivery collapses and a distinct capture
 * does not.
 *
 * SETTLEMENT IS PER BATCH, which the route earns: ingest is atomic per request,
 * so an ack covers every event in it and no per-row verdict is needed. What the
 * ack must show is that the deployment actually took them — `accepted +
 * duplicates`, exactly the rule the live forward stamps on. A `{accepted: 0,
 * duplicates: 0}` answer stamps NOTHING and the rows stay owed; today's backend
 * cannot produce one, but the wire contract permits it and this plugin talks to
 * deployments it does not ship. The unread case costs a redundant resend, never
 * a silently dropped row.
 */
async function drainCaptures(
  d: DrainDeps,
  deadline: number,
  beat: () => void,
): Promise<ChunkResult> {
  let sent = 0;
  let skipped = 0;

  for (;;) {
    if (d.now() >= deadline) return { sent, skipped, stopped: 'interrupted' };

    // Re-read each time rather than paging with an offset: the previous
    // iteration stamped or skipped everything it took, so the unstamped set has
    // shrunk and the next page is simply the new head of it. An offset over a
    // set being mutated underneath would step past rows.
    // `backlogBefore` is the attachment boundary, and this lane reads the side of
    // it the structural lane does not: captures recorded FROM the attachment
    // onwards, which the live path owed and did not deliver. Older captures are
    // pre-attach history and belong to the structural lane, which sends them
    // without their text — draining them here would put a machine's whole local
    // history of prompts on the wire under copy that promises the opposite.
    const rows = d.ledger.pendingCaptureRows(
      CAPTURE_BATCH_SIZE,
      d.backlogBefore,
      d.now() - CAPTURE_GRACE_MS,
    );
    if (rows.length === 0) return { sent, skipped };

    const ready: { id: string; event: IngestEvent }[] = [];
    const unbuildable: string[] = [];
    for (const row of rows) {
      const event = rebuildCapture(row);
      if (event === undefined) {
        // A local defect, not an outage. Retrying for ever would stall the lane
        // behind one unexpressible row — and because this read has no cursor,
        // that row would be the head of every subsequent page.
        unbuildable.push(row.id);
        continue;
      }
      ready.push({ id: row.id, event });
    }
    // ONE write for the page rather than one per row: markSkipped takes a list,
    // and each call is its own IMMEDIATE transaction competing for the store's
    // write lock with the live capture path.
    if (unbuildable.length > 0) {
      d.ledger.markSkipped(unbuildable);
      skipped += unbuildable.length;
    }
    if (ready.length === 0) {
      // BEFORE the continue, not after it. Every statement on this path —
      // pendingCaptureRows, rebuildCapture, markSkipped — is synchronous, so a
      // run of unbuildable rows would otherwise be a loop that never yields and
      // never checks in. Twenty thousand rows carrying an attribute the wire
      // rejects is one uninterrupted synchronous stretch: no heartbeat past
      // HISTORY_LEASE_STALE_MS, so a second child takes the claim from a drain
      // that is alive, and no yield at all, so the event loop is held for the
      // whole pass budget.
      beat();
      await d.sleep(PACE_INTERVAL_MS);
      continue;
    }

    const result = await sendCaptureChunk(d, ready, beat);
    sent += result.sent;
    skipped += result.skipped;
    if (result.stopped !== undefined) return { sent, skipped, stopped: result.stopped };

    // Nothing sent and nothing skipped would mean the loop re-reads the same
    // head and calls the same failing send for ever. It cannot happen —
    // sendCaptureChunk either settles, skips, or stops — but the read has no
    // cursor, so the one shape that could stall is worth refusing outright
    // rather than trusting a caller three levels down to keep the invariant.
    if (result.sent === 0 && result.skipped === 0) return { sent, skipped, stopped: 'unreachable' };

    beat();
    await d.sleep(PACE_INTERVAL_MS);
  }
}

/**
 * Send one batch of captures, isolating a permanent rejection rather than
 * retrying it for ever.
 *
 * The structural lane learned this the same way: a batch ack is an AGGREGATE, so
 * a rejection names no row. Re-sending the identical body fails identically, and
 * marking the whole batch skipped would discard as many as 99 good rows for one
 * bad one. The capture lane is MORE exposed than the structural one, not less —
 * its batches are twice the size, every row carries user text, and
 * `ingestEvents` does no outbound validation of its own — and its read has no
 * cursor, so a rejected row stays the head of every future page. Without this,
 * one bad row silently retires the whole lane while status reports 'unreachable'.
 */
async function sendCaptureChunk(
  d: DrainDeps,
  chunk: readonly { id: string; event: IngestEvent }[],
  beat: () => void,
): Promise<ChunkResult> {
  // THE SAME LADDER THE STRUCTURAL LANE CLIMBS, not a single attempt. A 503 or a
  // socket timeout is exactly the failure a retry exists for, and returning on
  // the first one would end the whole capture drain for the pass inside a 120s
  // budget with room for four attempts — so on a deployment that blips once per
  // pass the capture backlog would never shrink while the structural lane behind
  // it drained normally.
  const outcome = await sendCapturesWithRetries(d, chunk, beat);
  if (outcome.verdict === 'refused') return { sent: 0, skipped: 0, stopped: 'refused' };
  if (outcome.verdict === 'unreachable') return { sent: 0, skipped: 0, stopped: 'unreachable' };
  if (outcome.verdict === 'sent') {
    const settled = outcome.settled;
    // The deployment did not take the whole batch. `IngestAck` constrains
    // `accepted` and `duplicates` only to be non-negative, so a partial answer
    // is permitted by the contract even though today's backend keeps
    // accepted + duplicates == events.length on every return path — and this
    // plugin talks to deployments it does not ship.
    //
    // The comparison is against `chunk.length`, not against 0, and that is the
    // whole point: a 100-row batch answered {accepted: 40} would otherwise stamp
    // all 100 delivered and never offer the other 60 again, with the ledger
    // reading "delivered" for rows that were not. Under-counting costs a
    // redundant resend the receiver's id-dedup absorbs; over-counting is silent
    // data loss, so the unread case has to fall on the resend side.
    if (settled < chunk.length) return { sent: 0, skipped: 0, stopped: 'unreachable' };
    d.ledger.markSynced(
      chunk.map((c) => c.id),
      d.now(),
    );
    return { sent: chunk.length, skipped: 0 };
  }

  {
    // Rejected on its merits (400/413/422, or a body this client refused to
    // send). One row is at fault and the answer does not say which.
    const only = chunk.length === 1 ? chunk[0] : undefined;
    if (only !== undefined) {
      d.ledger.markSkipped([only.id]);
      return { sent: 0, skipped: 1 };
    }
    let sent = 0;
    let skipped = 0;
    for (const [index, one] of chunk.entries()) {
      // PACED like every other request, for the reason the structural lane
      // gives: the isolation pass must not burst one request per row at the
      // moment the deployment has just refused something, on a credential this
      // job shares with the live forwarding.
      if (index > 0) await d.sleep(PACE_INTERVAL_MS);
      beat();
      const single = await sendCaptureChunk(d, [one], beat);
      sent += single.sent;
      skipped += single.skipped;
      if (single.stopped !== undefined) return { sent, skipped, stopped: single.stopped };
    }
    return { sent, skipped };
  }
}

/**
 * One capture batch, retried on the failures that might not repeat.
 *
 * The capture twin of `sendWithRetries`, separate only because it has an ack to
 * carry back rather than a bare verdict. Same ladder, same full-jitter backoff,
 * same reason: machines that failed together must not retry together.
 */
async function sendCapturesWithRetries(
  d: DrainDeps,
  chunk: readonly { id: string; event: IngestEvent }[],
  beat: () => void,
): Promise<{ verdict: 'sent'; settled: number } | { verdict: Exclude<RowVerdict, 'sent'> }> {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    try {
      const ack = await d.sendCaptures(chunk.map((c) => c.event));
      return { verdict: 'sent', settled: ack.settled };
    } catch (err) {
      const kind = classify(err);
      if (kind === 'refused') return { verdict: 'refused' };
      if (kind === 'skip') return { verdict: 'skip' };
      if (attempt === MAX_ATTEMPTS - 1) return { verdict: 'unreachable' };
      const ceiling = Math.min(MAX_BACKOFF_MS, 1_000 * 2 ** attempt);
      // Before the sleep, for the reason the structural ladder gives: the gap
      // this covers is the request that just timed out plus the wait after it.
      beat();
      await d.sleep(Math.floor(d.random() * ceiling));
    }
  }
  return { verdict: 'unreachable' };
}

/**
 * Send one batch, and fall back to sending it row by row if it is rejected.
 *
 * The batch ack is an AGGREGATE count — there is no per-item verdict, and a
 * rejection therefore names no row. Re-sending the same batch would fail
 * identically for ever, and marking all of it skipped would discard as many as
 * 49 good rows for one bad one. Isolating costs one request per row of one
 * batch, and only on a path that should not normally be reached: the client
 * validates its own body before sending.
 */
async function sendChunk(
  d: DrainDeps,
  chunk: readonly { id: string; event: RecordAuditEventRequest }[],
  beat: () => void,
): Promise<ChunkResult> {
  const verdict = await sendWithRetries(
    d,
    chunk.map((c) => c.event),
    beat,
  );
  if (verdict === 'sent') {
    d.ledger.markSynced(
      chunk.map((c) => c.id),
      d.now(),
    );
    return { sent: chunk.length, skipped: 0 };
  }
  if (verdict === 'refused' || verdict === 'unreachable') {
    return { sent: 0, skipped: 0, stopped: verdict };
  }
  // Rejected on its merits. One row is at fault and the answer does not say
  // which, so find it rather than lose the batch.
  const only = chunk.length === 1 ? chunk[0] : undefined;
  if (only !== undefined) {
    d.ledger.markSkipped([only.id]);
    return { sent: 0, skipped: 1 };
  }
  let sent = 0;
  let skipped = 0;
  for (const [index, one] of chunk.entries()) {
    // PACED like every other request. The pause between batches lives in the
    // caller, so without this the isolation pass would fire one request per row
    // back to back — a burst as large as the batch, at the moment the deployment
    // has just refused something, on a credential this job shares with the live
    // forwarding it must never be the reason to rate-limit.
    if (index > 0) await d.sleep(PACE_INTERVAL_MS);
    beat();
    const single = await sendChunk(d, [one], beat);
    sent += single.sent;
    skipped += single.skipped;
    if (single.stopped !== undefined) return { sent, skipped, stopped: single.stopped };
  }
  return { sent, skipped };
}

/**
 * Send one request, retrying only what might not repeat.
 *
 * The transport makes no retries by construction and forbids adding one there,
 * so the ladder lives here — where the caller owns the decision and the traffic
 * it produces is bounded by a pass budget rather than by a fail-open hook.
 */
async function sendWithRetries(
  d: DrainDeps,
  events: readonly RecordAuditEventRequest[],
  beat: () => void,
): Promise<RowVerdict> {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    try {
      await d.send(events);
      return 'sent';
    } catch (err) {
      const kind = classify(err);
      if (kind === 'refused') return 'refused';
      if (kind === 'skip') return 'skip';
      if (attempt === MAX_ATTEMPTS - 1) return 'unreachable';
      // Full jitter: several machines that failed together must not retry
      // together. The deployment's own retry-after is not available — the
      // transport carries the status alone, deliberately, so that a
      // server-authored string can never reach a log or a status line.
      const ceiling = Math.min(MAX_BACKOFF_MS, 1_000 * 2 ** attempt);
      // Before the sleep, not after: the gap this covers is the request that
      // just timed out plus the wait that follows it.
      beat();
      await d.sleep(Math.floor(d.random() * ceiling));
    }
  }
  return 'unreachable';
}

/**
 * The status a failure carries, read STRUCTURALLY.
 *
 * Never `instanceof`, for the reason the sibling classifier gives: this module is
 * bundled into every hook script while the transport is a separate package, and
 * a prototype identity that survives one bundler configuration is not a thing to
 * hang a verdict on. Reading the field also catches the class that is easy to
 * miss — the transport error carries a status too, on the two paths where
 * headers arrived and only the body was refused, so a 401 answered with an
 * oversized body would otherwise read as a network outage and be retried four
 * times before reporting "unreachable" to a user who needs to re-attach.
 */
function statusOf(err: unknown): number | null {
  if (typeof err !== 'object' || err === null || !('status' in err)) return null;
  const { status } = err;
  if (typeof status !== 'number' || !Number.isInteger(status)) return null;
  return status >= 100 && status <= 599 ? status : null;
}

/** What a failure means for the pass. */
function classify(err: unknown): 'refused' | 'skip' | 'retry' {
  // A body this client refused to SEND is a defect on this machine, not an
  // outage — it fails identically on every attempt and against every deployment.
  if ((err as { name?: string }).name === 'RemoteRequestInvalid') return 'skip';
  switch (statusOf(err)) {
    // Terminal in a way a timeout is not: the credential may have died with an
    // offboarded member, and every later row would fail the same way.
    case 401:
    case 403:
      return 'refused';
    // The deployment understood the request and rejected it. Re-sending an
    // identical body cannot change that.
    case 400:
    case 413:
    case 422:
      return 'skip';
    default:
      return 'retry';
  }
}
