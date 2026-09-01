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
import { AUDIT_EVENT_BATCH_MAX, isAttached, isHistorySyncConsentValid } from '@akasecurity/schema';

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

    const send =
      deps.sendBatch ??
      (() => {
        const client = createRemoteClient({
          endpoint: connection.endpoint,
          apiKey: state.credential.apiKey,
          timeoutMs: HISTORY_REQUEST_TIMEOUT_MS,
        });
        return async (events: readonly RecordAuditEventRequest[]): Promise<void> => {
          // The client falls back to one request per event against a deployment
          // that predates the batch route, so this call is correct against both.
          await client.recordAuditEvents(events);
        };
      })();

    try {
      return await drain({ ledger, send, now, sleep, random, budgetMs, pid, backlogBefore });
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
  let sent = 0;
  let skipped = 0;
  let lastHeartbeat = startedAt;
  let outcome: HistorySyncOutcome = 'ok';

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

  outer: while (d.now() < deadline) {
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
        if (d.now() >= deadline) {
          outcome = 'interrupted';
          break outer;
        }
        const chunk = ready.slice(i, i + BATCH_SIZE);
        const result = await sendChunk(d, chunk, beat);
        sent += result.sent;
        skipped += result.skipped;
        if (result.stopped !== undefined) {
          // Everything not acknowledged stays pending, by doing nothing.
          outcome = result.stopped;
          break outer;
        }

        beat();
        await d.sleep(PACE_INTERVAL_MS);
      }
    }
  }

  if (outcome === 'ok' && d.now() >= deadline && d.ledger.counts(d.backlogBefore).pending > 0) {
    outcome = 'interrupted';
  }
  return { outcome, sent, skipped, counts: d.ledger.counts(d.backlogBefore), atMs: d.now() };
}

interface ChunkResult {
  sent: number;
  skipped: number;
  /** Set when the pass must stop; everything else stays pending. */
  stopped?: HistorySyncOutcome;
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
