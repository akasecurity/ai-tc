// Presentational lookups + pure derivations for the Exceptions views. Lives in
// @akasecurity/dashboard-ui so every host renders
// identical state/scope/provenance labelling.
import type {
  BlockedDetection,
  DetectionException,
  FingerprintKeyState,
} from '@akasecurity/schema';
import { isMatchableUnder } from '@akasecurity/schema';
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
 * The ledger is retained for a day, which is longer than a key rotation takes,
 * so the strip keeps listing rows fingerprinted under a key that is no longer
 * current — still an accurate record of what was blocked, just no longer grant
 * material. This mirrors the server-side refusal, which is the actual control;
 * the UI use of it only avoids offering a click that cannot succeed.
 *
 * Delegates to the shared rule rather than restating it, so the strip and the
 * two approve surfaces cannot drift on which rows are usable.
 */
export function isBlockedRowApprovable(
  row: Pick<BlockedDetection, 'keyVersion'>,
  key: FingerprintKeyState,
): boolean {
  return isMatchableUnder(row.keyVersion, key);
}

/**
 * Why a row cannot be approved, as something to show the reader — the three key
 * states are three different problems, and only one of them is solved by
 * triggering the detection again.
 */
export function blockedRowBlockReason(
  row: Pick<BlockedDetection, 'keyVersion'>,
  key: FingerprintKeyState,
): string | null {
  if (isBlockedRowApprovable(row, key)) return null;
  switch (key.status) {
    case 'unreadable':
      // Nothing changed and nothing is lost: the key is fine once its
      // permissions are. Telling this reader to re-trigger would be wrong, and
      // telling them to delete the key would destroy every grant they have.
      return 'The fingerprint key file cannot be read, so no recorded detection can be matched right now. Check the permissions on ~/.aka/data — do not delete the key.';
    case 'absent':
      return 'The fingerprint key file is missing, so the fingerprint recorded for this detection can no longer be matched. Trigger the detection again.';
    default:
      return `Recorded under fingerprint key v${String(row.keyVersion)}; the key is now v${String(key.version)}, so a grant from it could never match. Trigger the detection again.`;
  }
}

/**
 * The blocked-ledger retention window, in hours, as the rotate note names it.
 *
 * The count the note carries is taken over the ledger's whole retention window,
 * while the strip behind the dialog shows whichever lookback chip is selected —
 * 30 minutes by default. So the number routinely exceeds what is on screen, and
 * a reader who cannot reconcile the two has been given a figure they cannot
 * trust. Naming the window is what makes it reconcilable.
 *
 * The authority is BLOCKED_DETECTIONS_RETENTION_MS in @akasecurity/persistence,
 * which this package does not depend on and must not. Hosts that have both pin
 * them together instead.
 */
export const LEDGER_WINDOW_HOURS = 24;

/**
 * What a key rotation costs the blocked-detections ledger, as a line the rotate
 * dialog shows before the user commits.
 *
 * The ledger is retained for a day, so it routinely outlives a rotation, and
 * every row in it carries a fingerprint recorded under the key that was current
 * when the detection was blocked. After rotating, none of them can be turned
 * into a grant. The rows are not removed — they stay as a record of what was
 * blocked — and the server-side refusal is the actual control; this is the
 * "tell them before, not after" half.
 *
 * `stillApprovable` counts the rows matchable under the CURRENT key — the same
 * predicate the strip disables its Approve button on, so the dialog's number
 * and the buttons the user can see agree. That is also its limit: like the
 * strip, it counts a row whose grant is already active, because neither models
 * grant state.
 */
export function rotationBlockedLedgerNote(stillApprovable: number): string {
  if (stillApprovable <= 0) {
    // No number, so no window to name — this variant claims nothing the reader
    // could try to reconcile with the strip behind the dialog.
    return 'Recently blocked detections are invalidated too: the ledger outlives a rotation, so its rows stay listed as a record of what was blocked but stop being approvable. Trigger the detection again to approve it under the new key.';
  }
  const window = `from the last ${String(LEDGER_WINDOW_HOURS)} hours`;
  const subject =
    stillApprovable === 1
      ? `1 recently blocked detection ${window} is still approvable; after rotating, none are`
      : `${String(stillApprovable)} recently blocked detections ${window} are still approvable; after rotating, none are`;
  return `${subject}. They stay listed as a record of what was blocked — trigger the detection again to approve under the new key.`;
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

// Capability labels — what a grant authorizes. Suppression is the default and
// renders unlabelled in the views; reveal-to-model is called out loudly because
// it lets the value's raw form reach the model at tool boundaries.
export const CAPABILITY_LABEL: Record<DetectionException['capability'], string> = {
  suppress: 'Suppress',
  reveal_to_model: 'Reveal to model',
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
