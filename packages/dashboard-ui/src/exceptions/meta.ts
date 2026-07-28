// Presentational lookups + pure derivations for the Exceptions views. Lives in
// @akasecurity/dashboard-ui so every host renders
// identical state/scope/provenance labelling.
import type { BlockedDetection, DetectionException } from '@akasecurity/schema';
import type { BadgeProps } from '@akasecurity/ui-kit';

export type Tone = NonNullable<BadgeProps['variant']>;

// Derived exception lifecycle state — NEVER stored (mirrors the persistence
// repository's ACTIVE_PREDICATE and the CLI's stateOf): a grant applies while
// it is unrevoked, unexpired, and under its use budget.
export type ExceptionState = 'active' | 'consumed' | 'expired' | 'revoked';

export function exceptionState(ex: DetectionException, now = Date.now()): ExceptionState {
  if (ex.revokedAt !== null) return 'revoked';
  if (ex.maxUses !== null && ex.useCount >= ex.maxUses) return 'consumed';
  if (ex.expiresAt !== null && Date.parse(ex.expiresAt) <= now) return 'expired';
  return 'active';
}

/**
 * Whether a blocked-ledger row can still be turned into a grant.
 *
 * The row's fingerprint was computed under whichever key was live when the hook
 * blocked. Enforcement fingerprints under the CURRENT key and scopes its bundle
 * query to that version, so a grant built from a row keyed to any other version
 * could never match. The ledger is retained for a day, which is longer than a
 * key rotation takes, so the strip keeps listing such rows — they are still an
 * accurate record of what was blocked, just no longer grant material.
 *
 * `currentKeyVersion` is null when there is no key file at all; the material is
 * gone, so no stored fingerprint can be reproduced and nothing is approvable.
 * This mirrors the server-side refusal, which is the actual control — this only
 * keeps the UI from offering a click that cannot succeed.
 */
export function isBlockedRowApprovable(
  row: Pick<BlockedDetection, 'keyVersion'>,
  currentKeyVersion: number | null,
): boolean {
  return currentKeyVersion !== null && row.keyVersion === currentKeyVersion;
}

export const STATE_TONE: Record<ExceptionState, Tone> = {
  active: 'success',
  consumed: 'default',
  expired: 'default',
  revoked: 'critical',
};

export const SCOPE_LABEL: Record<DetectionException['scope'], string> = {
  once: 'Once',
  temporary: 'Temporary',
  permanent: 'Permanent',
};

// Provenance labels — how the grant was created.
export const VIA_LABEL: Record<DetectionException['createdVia'], string> = {
  'cli-approve': 'CLI approve',
  'cli-add': 'CLI add',
  'web-approve': 'Web approve',
  'web-add': 'Web add',
  api: 'API',
  'setup-triage': 'Setup triage',
};

/** The scope answers the grant forms offer; resolved server-side via scopeFromAnswer. */
export const SCOPE_ANSWERS = ['once', '30m', '1h', '24h', 'permanent'] as const;
export type ScopeAnswer = (typeof SCOPE_ANSWERS)[number];

export const SCOPE_ANSWER_LABEL: Record<ScopeAnswer, string> = {
  once: 'Once',
  '30m': '30 min',
  '1h': '1 hour',
  '24h': '24 hours',
  permanent: 'Permanent',
};
