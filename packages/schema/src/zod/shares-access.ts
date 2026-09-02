import {
  DATA_CLASS_ORDER,
  type DataClass,
  type EgressDecision,
  type EgressStatus,
  type ReviewInfo,
  type ReviewReason,
  type ShareTrustLevel,
  type Transport,
} from './shares.ts';

/**
 * Pure, no-I/O derivation helpers for the Data Shares read path. These compute
 * posture (review reasons, trust default, rollups) from already-fetched rows;
 * nothing here touches the database.
 *
 * These live in `@akasecurity/schema` so every read port shares ONE
 * definition of what "needs review"/"blocked"
 * means — a divergence here would be a silent security-posture split with no
 * compiler or test to catch it. Same treatment as BUILTIN_POLICIES in policy.ts.
 */

// ---------------------------------------------------------------------------
// Effective status / isCustom
// ---------------------------------------------------------------------------

/** Trust levels that resolve to 'allowed' absent any egress decision override. */
const ALLOWED_BY_DEFAULT_TRUST = new Set<ShareTrustLevel>(['recognized', 'internal']);

/** The effective status a destination's trust alone resolves to, before any override. */
export function trustDefaultStatus(trust: ShareTrustLevel): EgressStatus {
  return ALLOWED_BY_DEFAULT_TRUST.has(trust) ? 'allowed' : 'review';
}

/** Maps a stored egress decision to the effective status it forces. */
export function decisionToStatus(decision: EgressDecision): EgressStatus {
  return decision === 'block' ? 'blocked' : 'allowed';
}

/** The effective status from the trust default plus any override decision. */
export function effectiveStatus(
  trust: ShareTrustLevel,
  overrideDecision: EgressDecision | null,
): EgressStatus {
  return overrideDecision === null ? trustDefaultStatus(trust) : decisionToStatus(overrideDecision);
}

/**
 * True when an egress decision override exists AND resolves to a different
 * effective status than the trust default would produce on its own. A
 * redundant `allow` on an already-allowed destination is NOT custom.
 */
export function isCustomDecision(
  trust: ShareTrustLevel,
  overrideDecision: EgressDecision | null,
): boolean {
  if (overrideDecision === null) return false;
  return decisionToStatus(overrideDecision) !== trustDefaultStatus(trust);
}

// ---------------------------------------------------------------------------
// Review posture
// ---------------------------------------------------------------------------

/**
 * Derives the posture review reasons for a destination: `raw_ip` when trust is
 * 'ip', `unverified_domain` when trust is 'unverified', `plaintext_transport`
 * when at least one endpoint uses an unencrypted transport ('http' or 'ws';
 * 'https' and 'wss' are encrypted).
 *
 * Independent of any egress decision override, and stays that way: these are
 * the reasons a destination WAS flagged, and blocking it does not stop it
 * being a raw IP. The reasons remain worth showing on a decided destination —
 * it is the review FLAG that clears, in `buildReviewInfo` one layer up, not
 * the explanation.
 */
export function deriveReviewReasons(
  trust: ShareTrustLevel,
  transports: Transport[],
): ReviewReason[] {
  const reasons: ReviewReason[] = [];
  if (trust === 'ip') reasons.push('raw_ip');
  if (trust === 'unverified') reasons.push('unverified_domain');
  if (transports.includes('http') || transports.includes('ws')) reasons.push('plaintext_transport');
  return reasons;
}

/**
 * Builds the `{ needsReview, reasons }` object: the reasons a destination is
 * flagged, plus whether an operator still has to look at it.
 *
 * `needsReview` is a WORK QUEUE, not a posture readout — the "Needs review N"
 * banner is the register's to-do list. A queue an operator cannot empty by
 * acting is decoration, so writing an egress decision takes the destination
 * out of it while the reasons stay to say why it was ever in.
 *
 * `decided` is "an override row exists", NOT `isCustomDecision`. The two part
 * company on exactly the case that matters: a 'recognized' destination flagged
 * only for `plaintext_transport` already defaults to 'allowed', so an explicit
 * `allow` on it resolves to the same status and `isCustomDecision` reports
 * false. Keyed on that, the one destination an operator has deliberately
 * cleared would sit in the queue forever — the very failure this argument
 * exists to fix.
 *
 * The argument is required rather than defaulted because there are two engines
 * deriving this posture (this fold, and the SQL aggregates behind the KPI
 * tiles) and they have drifted before. A caller that has not thought about the
 * decision should fail to compile, not silently inherit a default.
 */
export function buildReviewInfo(
  trust: ShareTrustLevel,
  transports: Transport[],
  decided: boolean,
): ReviewInfo {
  const reasons = deriveReviewReasons(trust, transports);
  return { needsReview: reasons.length > 0 && !decided, reasons };
}

// ---------------------------------------------------------------------------
// Rollups — transports / dataClasses across a destination's endpoints
// ---------------------------------------------------------------------------

/** Distinct transports across a destination's endpoints, first-seen order preserved. */
export function distinctTransports(transports: Transport[]): Transport[] {
  return Array.from(new Set(transports));
}

/** Distinct data classes across a destination's endpoints, most-sensitive first. */
export function distinctDataClasses(dataClasses: DataClass[]): DataClass[] {
  const present = new Set(dataClasses);
  return DATA_CLASS_ORDER.filter((dc) => present.has(dc));
}

/**
 * The single most-sensitive data class across a destination's endpoints — the
 * needs-review strip's class chip. Falls back to 'none' (DataClass's own
 * least-sensitive sentinel) when the destination has no endpoints.
 */
export function topDataClass(dataClasses: DataClass[]): DataClass {
  return distinctDataClasses(dataClasses)[0] ?? 'none';
}

// ---------------------------------------------------------------------------
// ?review=true severity ordering
// ---------------------------------------------------------------------------

/**
 * Severity ranking for the needs-review strip ordering — lower rank sorts
 * first. Matches the contract's "ip → unverified_domain → plaintext_transport"
 * order.
 */
export const REVIEW_SEVERITY_RANK: Record<ReviewReason, number> = {
  raw_ip: 0,
  unverified_domain: 1,
  plaintext_transport: 2,
};

/** The most severe rank among a destination's review reasons (lower = more severe). */
export function reviewSeverityRank(reasons: ReviewReason[]): number {
  if (reasons.length === 0) return Number.POSITIVE_INFINITY;
  return Math.min(...reasons.map((r) => REVIEW_SEVERITY_RANK[r]));
}
