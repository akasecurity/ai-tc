import type { SessionAccountObservation } from '@akasecurity/schema';

import { claudeKey } from './account-check.ts';
import type { LoggedObservation } from './observation-log.ts';
import { classifyObservation, sessionAccountHash } from './observation-log.ts';

// Which account each transcript record ran under. Pure over the parsed chunk,
// the session log from the last consumed offset, and the state carried from the
// previous pass. The carry holds offsets and a hash of a work key, never an org.

export type TranscriptMark =
  | { readonly kind: 'org'; readonly org: string; readonly t: number; readonly pos: number }
  | { readonly kind: 'record'; readonly id: string; readonly t: number };

export interface AttributionView {
  readonly t: number;
  readonly k: 'w' | 'n' | 'v';
  readonly h?: string | undefined;
}

export interface AttributionCarry {
  readonly anchorAt?: number | undefined;
  readonly changedAt?: number | undefined;
  readonly lastOrgAt?: number | undefined;
  readonly boundaryAt?: number | undefined;
  readonly inherited: boolean;
  readonly lastObs?: AttributionView | undefined;
}

export const NO_ATTRIBUTION_CARRY: AttributionCarry = { inherited: false };

export interface AttributionInput {
  /** This chunk's credential_org sightings and records, in file order. */
  readonly marks: readonly TranscriptMark[];
  /** The session log from `logOffset` on. */
  readonly observations: readonly LoggedObservation[];
  readonly logOffset: number;
  readonly carry: AttributionCarry;
  /** The org on the line at `carry.anchorAt`, read again by the caller. */
  readonly anchorOrg: string | undefined;
  /** The org on the line at `carry.lastOrgAt`, read again by the caller. */
  readonly lastOrg: string | undefined;
  readonly bindingHash: string;
  /** Whether this account's agent key is in the resolved scope now. */
  readonly inScope: (accountKey: string) => boolean;
}

export type RecordAttribution =
  | { readonly status: 'account'; readonly key: string }
  | { readonly status: 'none' }
  | { readonly status: 'pending' };

export interface AttributionResult {
  readonly records: ReadonlyMap<string, RecordAttribution>;
  readonly carry: AttributionCarry;
  /** Consumed only through the chunk's last record, so later views stay for the next pass. */
  readonly logOffset: number;
  /**
   * The key of the account the session is in once the chunk's last record is written, whether
   * or not any record is attributed to it: the key of the org the credential_org lines name
   * since the last boundary, when the chunk ran under one boundary and that key is in scope,
   * and the latest view at or after the last record, before the next boundary, is a work view
   * for it. A record keeps its own attribution; this only names the account the session is in.
   */
  readonly closingAccount: string | undefined;
  /**
   * The key of the account the session is in by every test of `closingAccount` but the scope one:
   * its key is not in scope yet, so a check that learns the key makes this the closing account.
   * Undefined when `closingAccount` is named.
   */
  readonly unscopedAccount: string | undefined;
}

interface Boundary {
  readonly t: number;
  readonly kind: 'startup' | 'clear' | 'resume';
  readonly inherited: boolean;
}

const NONE: RecordAttribution = { status: 'none' };
const PENDING: RecordAttribution = { status: 'pending' };

function viewOf(
  observation: SessionAccountObservation,
  bindingHash: string,
): AttributionView | undefined {
  const line = classifyObservation(observation);
  if (line.kind !== 'view' || line.k === 'u' || line.bd !== bindingHash) return undefined;
  return { t: line.t, k: line.k, h: line.h };
}

/**
 * A record is attributed to K only when its anchor is K with no different
 * credential_org since, the nearest readable views of this binding on both
 * sides of it are work views for K with no boundary between them, and K's
 * agent key is in scope now. A view at the record's own time is its view
 * after; the view before is strictly earlier. With no view after it yet, it
 * is pending.
 */
export function attributeRecords(input: AttributionInput): AttributionResult {
  if (input.marks.length === 0) {
    return {
      records: new Map(),
      carry: input.carry,
      logOffset: input.logOffset,
      closingAccount: undefined,
      unscopedAccount: undefined,
    };
  }
  const views: AttributionView[] = input.carry.lastObs === undefined ? [] : [input.carry.lastObs];
  const boundaries: Boundary[] = [];
  for (const { observation } of input.observations) {
    const line = classifyObservation(observation);
    if (line.kind === 'boundary') {
      boundaries.push({ t: line.t, kind: line.b, inherited: false });
    } else if (line.kind === 'inherit') {
      const last = boundaries.at(-1);
      if (line.bd === input.bindingHash && last?.kind === 'resume' && line.t >= last.t) {
        boundaries[boundaries.length - 1] = { ...last, inherited: true };
      }
    } else {
      const view = viewOf(observation, input.bindingHash);
      if (view !== undefined) views.push(view);
    }
  }

  let boundaryAt = input.carry.boundaryAt;
  let inherited = input.carry.inherited;
  let anchorAt = input.carry.anchorAt;
  let anchorOrg = anchorAt === undefined ? undefined : input.anchorOrg;
  let lost = anchorAt !== undefined && input.anchorOrg === undefined;
  let changedAt = input.carry.changedAt;
  let lastOrgAt = input.carry.lastOrgAt;
  let lastOrg = lastOrgAt === undefined ? undefined : input.lastOrg;
  let next = 0;
  let segment = 0;

  const apply = (boundary: Boundary): void => {
    segment += 1;
    boundaryAt = boundary.t;
    inherited = boundary.kind === 'resume' && boundary.inherited;
    changedAt = undefined;
    lost = false;
    anchorOrg = inherited ? lastOrg : undefined;
    anchorAt = inherited ? lastOrgAt : undefined;
  };
  const applyThrough = (t: number): void => {
    for (
      let boundary = boundaries[next];
      boundary !== undefined && boundary.t <= t;
      boundary = boundaries[next]
    ) {
      apply(boundary);
      next += 1;
    }
  };
  const anchored = (
    inScopeOnly: boolean,
  ): { readonly accountKey: string; readonly floor: number } | undefined => {
    if (boundaryAt === undefined || lost || changedAt !== undefined || anchorOrg === undefined)
      return undefined;
    const accountKey = claudeKey(anchorOrg);
    return !inScopeOnly || input.inScope(accountKey)
      ? { accountKey, floor: boundaryAt }
      : undefined;
  };
  const attribute = (t: number): RecordAttribution => {
    const anchor = anchored(true);
    if (anchor === undefined) return NONE;
    const { accountKey, floor } = anchor;
    const ceiling = boundaries[next]?.t;
    let before: AttributionView | undefined;
    let after: AttributionView | undefined;
    for (const view of views) {
      if (view.t < t && view.t >= floor && (before === undefined || view.t >= before.t))
        before = view;
      if (
        view.t >= t &&
        (ceiling === undefined || view.t < ceiling) &&
        (after === undefined || view.t < after.t)
      ) {
        after = view;
      }
    }
    if (after === undefined) return ceiling === undefined ? PENDING : NONE;
    if (before === undefined) return NONE;
    const hash = sessionAccountHash(accountKey);
    return before.k === 'w' && before.h === hash && after.k === 'w' && after.h === hash
      ? { status: 'account', key: accountKey }
      : NONE;
  };

  const records = new Map<string, RecordAttribution>();
  let maxT = Number.NEGATIVE_INFINITY;
  let lastRecordT = Number.NEGATIVE_INFINITY;
  let firstRecordSegment: number | undefined;
  for (const mark of input.marks) {
    maxT = Math.max(maxT, mark.t);
    applyThrough(mark.t);
    if (mark.kind === 'record') {
      firstRecordSegment ??= segment;
      lastRecordT = Math.max(lastRecordT, mark.t);
      records.set(mark.id, attribute(mark.t));
      continue;
    }
    if (boundaryAt !== undefined && !lost && changedAt === undefined) {
      if (anchorOrg === undefined) {
        if (!inherited && mark.t >= boundaryAt) {
          anchorOrg = mark.org;
          anchorAt = mark.pos;
        }
      } else if (mark.org !== anchorOrg) {
        changedAt = mark.pos;
      }
    }
    lastOrg = mark.org;
    lastOrgAt = mark.pos;
  }
  applyThrough(maxT);

  const closing = (inScopeOnly: boolean): string | undefined => {
    const anchor = anchored(inScopeOnly);
    if (anchor === undefined || firstRecordSegment !== segment) return undefined;
    const { accountKey } = anchor;
    const ceiling = boundaries[next]?.t;
    let latest: AttributionView | undefined;
    for (const view of views) {
      if (
        view.t >= lastRecordT &&
        (ceiling === undefined || view.t < ceiling) &&
        (latest === undefined || view.t >= latest.t)
      ) {
        latest = view;
      }
    }
    return latest?.k === 'w' && latest.h === sessionAccountHash(accountKey)
      ? accountKey
      : undefined;
  };

  let logOffset = input.logOffset;
  let lastObs = input.carry.lastObs;
  for (const entry of input.observations) {
    const line = classifyObservation(entry.observation);
    if (Number.isNaN(line.t) || line.t > maxT) break;
    logOffset = entry.end;
    lastObs = viewOf(entry.observation, input.bindingHash) ?? lastObs;
  }
  const closingAccount = closing(true);
  return {
    records,
    carry: { anchorAt, changedAt, lastOrgAt, boundaryAt, inherited, lastObs },
    logOffset,
    closingAccount,
    unscopedAccount: closingAccount === undefined ? closing(false) : undefined,
  };
}

export const ATTRIBUTION_HOLD_MAX_PASSES = 3;
export const ATTRIBUTION_HOLD_MAX_AGE_MS = 15 * 60 * 1000;

export interface PendingHold {
  readonly passes: number;
  readonly since: number;
}

/**
 * Whether a pass with pending records writes nothing and keeps its offsets:
 * while one of them is under fifteen minutes old, for at most three passes.
 */
export function holdDecision(input: {
  readonly pendingTimes: readonly number[];
  readonly pending: PendingHold | undefined;
  readonly now: number;
}): { readonly hold: true; readonly pending: PendingHold } | { readonly hold: false } {
  const passes = input.pending?.passes ?? 0;
  if (passes >= ATTRIBUTION_HOLD_MAX_PASSES) return { hold: false };
  if (!input.pendingTimes.some((t) => input.now - t < ATTRIBUTION_HOLD_MAX_AGE_MS))
    return { hold: false };
  return { hold: true, pending: { passes: passes + 1, since: input.pending?.since ?? input.now } };
}
