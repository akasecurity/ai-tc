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
// Review posture (independent of any decision override)
// ---------------------------------------------------------------------------

/**
 * Derives the posture review reasons for a destination: `raw_ip` when trust is
 * 'ip', `unverified_domain` when trust is 'unverified', `plaintext_transport`
 * when at least one endpoint uses 'http'. Independent of any egress decision
 * override — this is posture, not decision (an `allow` override still leaves
 * `needsReview: true` when the underlying posture is risky).
 */
export function deriveReviewReasons(
  trust: ShareTrustLevel,
  transports: Transport[],
): ReviewReason[] {
  const reasons: ReviewReason[] = [];
  if (trust === 'ip') reasons.push('raw_ip');
  if (trust === 'unverified') reasons.push('unverified_domain');
  if (transports.includes('http')) reasons.push('plaintext_transport');
  return reasons;
}

/** Builds the `{ needsReview, reasons }` object from the derived reasons. */
export function buildReviewInfo(trust: ShareTrustLevel, transports: Transport[]): ReviewInfo {
  const reasons = deriveReviewReasons(trust, transports);
  return { needsReview: reasons.length > 0, reasons };
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
