import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { ATTACHED_FORWARD_STATE_FILENAME } from './attached-derived.ts';

/**
 * How a control-plane call failed, as coarsely as anything is willing to say.
 *
 * ONE SOURCE, for the reason `sync-failure.ts` gives about its own list: the
 * writer and the readers must agree, and they live on opposite sides of this
 * package. The forward path classifies a failure and writes this value; the
 * status command and the dashboard render it; and a second spelling would be a
 * value that silently reads as "no cause recorded" rather than a type error.
 *
 *   `unauthorized` — the deployment knows this machine and refuses its key.
 *   `forbidden`    — the key is accepted and the call is not permitted.
 *   `unreachable`  — no verdict was obtained at all. The DEFAULT, and the
 *                    bucket for "no verdict we are willing to name", which is
 *                    why the surfaces that render it say what they observed
 *                    rather than guessing at a cause.
 */
export type ControlPlaneFailure = 'unauthorized' | 'forbidden' | 'unreachable';

/**
 * Validated on the way in, exactly as the sync outcome is: `lastFailure` is
 * RENDERED, so an arbitrary string from a hand-edited file must never reach the
 * output. An unrecognised value reads as null — no cause named — rather than as
 * a failure to parse the whole file, because the failure COUNT next to it is
 * still evidence and losing it would cost more than the cause.
 */
const FAILURES: ReadonlySet<string> = new Set<ControlPlaneFailure>([
  'unauthorized',
  'forbidden',
  'unreachable',
]);

/**
 * How long the breaker stays open before a single probe is allowed through.
 *
 * Sized against hook cadence rather than a server's recovery time: the point is
 * that a session's worth of hooks after a control plane goes down pays the
 * timeout once, not once per hook.
 *
 * HERE rather than beside the breaker, because three things now apply it and
 * one of them may not import the plugin runtime: the forward path that opens
 * the breaker, the history drain that declines to run while it is open, and the
 * dashboard, which otherwise has no way to say why a pass a user asked for did
 * nothing at all.
 */
export const BREAKER_COOLDOWN_MS = 30_000;

/**
 * What the breaker knows, for a READ-ONLY consumer.
 *
 * This file records BREAKER BOOKKEEPING ONLY — a failure count, the instant the
 * breaker opened, and a three-member enum naming HOW the last attempt failed. It
 * never holds a payload and never holds a credential. `lastFailure` is an enum
 * rather than an error string for that reason: a message from a failed request
 * can carry the URL, a header echo, or a fragment of the body that was being
 * sent — and the body on this path IS the event content. The only way to be sure
 * none of that is written next to a session's telemetry is to have nothing to
 * redact, so the classification happens in memory and the classification alone
 * is stored.
 */
export interface ForwardHealth {
  /** Failures since the last success. Monotonic across probes until one lands. */
  consecutiveFailures: number;
  /**
   * When the breaker last opened, or null when closed.
   *
   * ⚠ NOT "how long forwarding has been broken". The forward path re-stamps
   * this on every half-open probe, so the gap to now is bounded by one cooldown
   * however long the control plane has been down. `consecutiveFailures` is the
   * duration-ish signal; this one only says "the last attempt failed, recently".
   */
  openedAtMs: number | null;
  /**
   * How the last failure failed, or null when nothing has failed since the last
   * success — and also null for a file written before this field existed, or one
   * carrying a value this build does not recognise.
   *
   * The three are collapsed on purpose. Every one of them means the same thing
   * to a renderer: there is no cause here that can be named, so say what is
   * known and stop. Splitting them would create states a caller has to handle
   * and cannot act on differently.
   */
  lastFailure: ControlPlaneFailure | null;
}

/**
 * Parse the state file's contents, or `null` when it says nothing usable.
 *
 * Shared by the forward path's own reader and by `readForwardHealth`, so the
 * two can never disagree about what a given file means — in particular about
 * the future-`openedAtMs` clamp below, which they would otherwise each have to
 * remember. The two callers differ only in how they treat `null`: the policy
 * resolves it to CLOSED (forward normally), while a status view says nothing.
 */
export function parseForwardHealth(raw: string, nowMs: number): ForwardHealth | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return null;
    const record = parsed as {
      consecutiveFailures?: unknown;
      openedAtMs?: unknown;
      lastFailure?: unknown;
    };
    const failures =
      typeof record.consecutiveFailures === 'number' && record.consecutiveFailures >= 0
        ? record.consecutiveFailures
        : 0;
    // A stamp we could not yet have written means the CLOCK moved, not that the
    // breaker is open — and reading it as open wedges forwarding off
    // PERMANENTLY. The cooling path early-returns without rewriting the file, so
    // `at - openedAtMs` stays strongly negative and every later process re-reads
    // the same future stamp and returns null again, with nothing left that can
    // move it back. It does not take hostility to produce one: a laptop that
    // suspends, wakes and takes an NTP correction BACKWARDS leaves behind a
    // stamp ahead of the corrected clock. Same rule as a torn read — a value we
    // cannot have authored reads as CLOSED.
    const openedAtMs =
      typeof record.openedAtMs === 'number' &&
      Number.isFinite(record.openedAtMs) &&
      record.openedAtMs <= nowMs
        ? record.openedAtMs
        : null;
    // Absent for every file written before this field existed, which is the
    // common case on an already-deployed device: it reads as "no cause
    // recorded", the same as an unrecognised one, and the count and stamp
    // beside it stay usable.
    const lastFailure =
      typeof record.lastFailure === 'string' && FAILURES.has(record.lastFailure)
        ? (record.lastFailure as ControlPlaneFailure)
        : null;
    return { consecutiveFailures: failures, openedAtMs, lastFailure };
  } catch {
    // TORN READ. A half-written or garbage file must never resolve to "open":
    // an open breaker is a decision to STOP sending the organization its own
    // telemetry, and no corrupt byte on disk should make that decision on the
    // operator's behalf.
    return null;
  }
}

/**
 * Read the breaker's bookkeeping WITHOUT touching it.
 *
 * Synchronous and strictly read-only: a status renderer is sync and total, and
 * a surface describing the breaker must never open, close or re-stamp it.
 * Returns `null` when the file is absent, unreadable or unusable, which the
 * caller renders as "nothing recorded" rather than as health — the happy path
 * writes no file at all, so an absent file genuinely means no failure has been
 * recorded, not that a forward has ever succeeded.
 */
export function readForwardHealth(dir: string, nowMs = Date.now()): ForwardHealth | null {
  try {
    return parseForwardHealth(
      readFileSync(join(dir, ATTACHED_FORWARD_STATE_FILENAME), 'utf8'),
      nowMs,
    );
  } catch {
    return null;
  }
}

/**
 * Whether forwarding is paused right now.
 *
 * OPEN MEANS WITHIN THE COOLDOWN, not merely "a stamp is present", and writing
 * that test once is the point of this function. The stamp is never cleared by
 * elapsing, and the half-open probe RE-STAMPS it before every attempt, clearing
 * it only on a forward that succeeds. Treating any stamp as open would hold a
 * caller off for the whole window in which the live path has resumed probing —
 * and on a flaky deployment each cooldown re-stamps, so the job that most needs
 * to make progress during a partial outage would be the one held off
 * indefinitely by a breaker refusing nothing.
 *
 * Three callers apply it: the forward path deciding whether to probe, the
 * history drain deciding whether a pass is worth making, and the dashboard,
 * which renders it. Spelled three times it would be three slightly different
 * answers to "is this machine sending", and the one a user reads would be the
 * one no test compares against a real breaker.
 */
export function isForwardPaused(health: ForwardHealth | null, nowMs: number): boolean {
  const openedAtMs = health?.openedAtMs ?? null;
  if (openedAtMs === null) return false;
  return nowMs - openedAtMs < BREAKER_COOLDOWN_MS;
}
