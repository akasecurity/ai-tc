// Detection exceptions: user-approved grants that let one specific detected
// value pass an enforcing (block/redact) policy. The match key is
// (ruleId, valueFingerprint) — the rule is the stable detection identity, and
// the fingerprint pins the grant to the value the user approved, ignoring only
// invisible padding characters (see stripInvisiblePadding). A
// value-free, rule-wide suppression is a policy change, not an exception.
import * as z from 'zod';

import { DetectionCategory } from './finding.ts';
import { ConfirmedBy, DismissMethod } from './recommendation-action.ts';

// How long a grant lives. Stored for reporting only — evaluation reads the
// derived state off expiresAt / maxUses / revokedAt, so a future scope (e.g.
// a fixed use budget) is a writer change, not an evaluator change:
//   once      → expiresAt = short backstop, maxUses = 1
//   temporary → expiresAt = creation + duration, maxUses = null
//   permanent → both null; lives until revoked
export const ExceptionScope = z.enum(['once', 'temporary', 'permanent']);
export type ExceptionScope = z.infer<typeof ExceptionScope>;

// Optional narrowing conditions, ANDed against the capture metadata when
// present. All-optional today (v1 writes none) — a forward-compatibility bag,
// so adding a condition is a schema field, never a table migration.
// `.strict()` is load-bearing: a plain object would silently STRIP an unknown
// condition written by a newer client, and a vanished AND-clause makes the
// grant BROADER than the user approved. Rejecting the whole row (readers skip
// malformed rows) is the fail-closed direction — the grant stops applying
// instead of widening.
export const ExceptionConditions = z
  .object({
    repo: z.string().optional(),
    sourceTool: z.string().optional(),
    provider: z.string().optional(),
  })
  .strict();
export type ExceptionConditions = z.infer<typeof ExceptionConditions>;

// What a grant authorizes. 'suppress' is today's semantics: the detection is
// not hard-enforced (block/redact downgrades). 'reveal_to_model' is strictly
// stronger: the vault may de-reference the value's pointer back to raw FOR THE
// MODEL at an interception point — and, being stronger, it also satisfies
// suppression (a revealed value is necessarily not blocked). A suppression
// grant never reveals: the two are distinct so no existing grant silently
// widens.
export const ExceptionCapability = z.enum(['suppress', 'reveal_to_model']);
export type ExceptionCapability = z.infer<typeof ExceptionCapability>;

// The base shape, used by both the local store and the wire bundle. NO
// `.meta({ id })`: an id would register it in Zod's global registry, which
// anything walking these schemas then picks up as a named component.
export const DetectionException = z.object({
  id: z.guid(),
  ruleId: z.string(),
  // Denormalized from the rule, for reporting — never matched on.
  category: DetectionCategory,
  // HMAC-SHA256 hex of the raw match under a machine-local key: a KEYED
  // fingerprint, never the raw value, and never reversible. Matching recomputes
  // the fingerprint from a fresh capture; the value itself is never stored.
  // Shape-constrained so a malformed — or accidentally raw — value is rejected
  // at the boundary rather than persisted.
  valueFingerprint: z.string().regex(/^[0-9a-f]{64}$/),
  // Version of the fingerprint key the grant was written under; a rotated key
  // invalidates old grants rather than silently mismatching them.
  keyVersion: z.number().int().positive(),
  // maskMatch() preview of the approved value — never the raw value.
  maskedValue: z.string(),
  capability: ExceptionCapability.default('suppress'),
  scope: ExceptionScope,
  expiresAt: z.iso.datetime().nullable(),
  maxUses: z.number().int().positive().nullable(),
  useCount: z.number().int().nonnegative(),
  lastUsedAt: z.iso.datetime().nullable(),
  // Mandatory: every grant carries the human reason it exists.
  justification: z.string().min(1),
  // The same reason as a label, beside the free text: one of the human
  // dismiss reasons, never a machine verdict. Null on a grant made before it
  // existed, or when the person picked none.
  method: DismissMethod.nullable().default(null),
  confirmedBy: ConfirmedBy.default('user'),
  conditions: ExceptionConditions.nullable(),
  createdBy: z.string(),
  createdVia: z.enum(['cli-approve', 'cli-add', 'web-approve', 'web-add', 'api', 'setup-triage']),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
  // Revocation is terminal and retained — consumed/expired/revoked rows are
  // audit evidence; nothing in the exception lifecycle hard-deletes.
  revokedAt: z.iso.datetime().nullable(),
  revokedBy: z.string().nullable(),
  revokeReason: z.string().nullable(),
});
export type DetectionException = z.infer<typeof DetectionException>;

// What rides the PolicyBundle: the evaluation subset only (no justification,
// no audit fields — the hook doesn't need them and the bundle stays small).
export const ExceptionBundleEntry = DetectionException.pick({
  id: true,
  ruleId: true,
  valueFingerprint: true,
  keyVersion: true,
  capability: true,
  expiresAt: true,
  maxUses: true,
  useCount: true,
  conditions: true,
});
export type ExceptionBundleEntry = z.infer<typeof ExceptionBundleEntry>;

// What a presentation surface may know about a grant. Carries no
// valueFingerprint — the keyed HMAC is a correlation key and must never reach
// a view layer or the browser, the same rule PointerDescriptor states for
// vault pointers. keyVersion stays: it is a bare key epoch, not a correlation
// key, and the views need it to say which grants a rotation invalidates.
//
// `valueFingerprint?: never` is what makes this an EXCLUSION rather than an
// omission. A plain omit still accepts a full store row — every property it
// asks for is present — so a surface typed against it would keep compiling if
// the projection call in front of it were dropped, and the fingerprint would
// be back in the browser with nothing red. The optional-never makes a row
// carrying the field unassignable, so the projection is enforced by the type
// rather than by whoever remembers to call it.
export const ExceptionDescriptor = DetectionException.omit({ valueFingerprint: true });
export type ExceptionDescriptor = z.infer<typeof ExceptionDescriptor> & {
  valueFingerprint?: never;
};

// Strip the keyed fingerprint from a grant row before it crosses to a view.
// Destructured rather than spread-and-deleted: with the exclusion above, a
// spread copy still carries `valueFingerprint: string` at the type level, so
// separating the key from the rest is what produces a value the return type
// accepts.
export function toExceptionDescriptor(exception: DetectionException): ExceptionDescriptor {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- binding the field is how it is dropped
  const { valueFingerprint: _fingerprint, ...rest } = exception;
  return rest;
}

// One "a detection was just blocked/redacted" record from the short-lived
// (30-minute) blocked-detections ledger: everything the approve flows — CLI
// and web-ui — need to create an exception without the user retyping the
// value: the KEYED FINGERPRINT and masked preview, never the raw value.
// `reference` is the short id shown in the block message. Plain TS interface
// (read-projection precedent): the ledger never crosses the public API.
export interface BlockedDetection {
  reference: string;
  ruleId: string;
  category: DetectionCategory;
  valueFingerprint: string;
  keyVersion: number;
  maskedValue: string;
  sessionId: string | null;
  repo: string | null;
  blockedAt: string; // ISO timestamp
}

// Insert shape: the persistence repo stamps blocked_at at write time.
export type BlockedDetectionInput = Omit<BlockedDetection, 'blockedAt'>;

// The ledger row minus its keyed fingerprint — the same egress rule, and the
// same optional-never exclusion, as ExceptionDescriptor. The approve flows
// round-trip `reference` and the server re-reads the full row, so the
// fingerprint never needs to leave it.
export type BlockedDetectionDescriptor = Omit<BlockedDetection, 'valueFingerprint'> & {
  valueFingerprint?: never;
};

/** Strip the keyed fingerprint from a ledger row before it crosses to a view. */
export function toBlockedDetectionDescriptor(row: BlockedDetection): BlockedDetectionDescriptor {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- binding the field is how it is dropped
  const { valueFingerprint: _fingerprint, ...rest } = row;
  return rest;
}

/**
 * What the machine's fingerprint key file amounts to right now.
 *
 * The three states need to stay apart because each one means a different thing
 * to the person reading the screen: `absent` and `unreadable` both leave every
 * stored fingerprint unmatchable, but only one of them is fixed by triggering
 * the detection again — the other is fixed by repairing the file's permissions,
 * and deleting the key to "fix" it would destroy every grant on the machine.
 * Collapsing them to `number | null` is what makes a UI say "the key changed"
 * about a key that did not change.
 */
export type FingerprintKeyState =
  { status: 'present'; version: number } | { status: 'absent' } | { status: 'unreadable' };

/**
 * Whether a stored fingerprint — an exception grant, or a blocked-ledger row —
 * can still be matched at enforcement time.
 *
 * Enforcement fingerprints under the CURRENT key and scopes its bundle query to
 * that version, so anything recorded under another version could never match: a
 * grant minted from it is inert the moment it is created. Both approve surfaces
 * and the dashboard's blocked strip gate on this, which is why it lives in the
 * one package all three may import — a second copy is how the server and the UI
 * come to disagree about which rows are usable.
 */
export function isMatchableUnder(keyVersion: number, key: FingerprintKeyState): boolean {
  return key.status === 'present' && key.version === keyVersion;
}

/**
 * The blocked-ledger retention window, in hours, as the rotate note names it.
 *
 * The count the note carries is taken over the ledger's whole retention window,
 * while the dashboard strip behind the dialog shows whichever lookback chip is
 * selected — 30 minutes by default. So the number routinely exceeds what is on
 * screen, and a reader who cannot reconcile the two has been given a figure
 * they cannot trust. Naming the window is what makes it reconcilable.
 *
 * The authority is BLOCKED_DETECTIONS_RETENTION_MS in @akasecurity/persistence,
 * which this package does not depend on and must not — persistence depends on
 * this one. Hosts that have both pin them together instead.
 */
export const LEDGER_WINDOW_HOURS = 24;

/**
 * What a key rotation costs the blocked-detections ledger, as a line the rotate
 * surfaces show before the user commits.
 *
 * The ledger is retained for a day, so it routinely outlives a rotation, and
 * every row in it carries a fingerprint recorded under the key that was current
 * when the detection was blocked. After rotating, none of them can be turned
 * into a grant. The rows are not removed — they stay as a record of what was
 * blocked — and the server-side refusal is the actual control; this is the
 * "tell them before, not after" half.
 *
 * `stillApprovable` counts the rows matchable under the CURRENT key — the same
 * predicate every approve surface gates on, so the number and the rows a user
 * can act on agree. That is also its limit: like the dashboard strip, it counts
 * a row whose grant is already active, because neither models grant state.
 *
 * It lives here, beside `isMatchableUnder`, for the same reason that predicate
 * does: `aka exception rotate-key` and the dashboard's rotate dialog disclose
 * the cost of one irreversible action, and a second copy is how two surfaces
 * come to state different costs for it. @akasecurity/dashboard-ui re-exports it
 * so the views keep their existing import.
 */
export function rotationBlockedLedgerNote(stillApprovable: number): string {
  if (stillApprovable <= 0) {
    // No number, so no window to name — this variant claims nothing the reader
    // could try to reconcile with the rows in front of them.
    return 'Recently blocked detections are invalidated too: the ledger outlives a rotation, so its rows stay listed as a record of what was blocked but stop being approvable. Trigger the detection again to approve it under the new key.';
  }
  const window = `from the last ${String(LEDGER_WINDOW_HOURS)} hours`;
  const subject =
    stillApprovable === 1
      ? `1 recently blocked detection ${window} is still approvable; after rotating, none are`
      : `${String(stillApprovable)} recently blocked detections ${window} are still approvable; after rotating, none are`;
  return `${subject}. They stay listed as a record of what was blocked — trigger the detection again to approve under the new key.`;
}

/**
 * What a key rotation costs the secret vault when its fingerprint refresh does
 * not reach every stored value, as a line the rotate surfaces show AFTER the
 * rotation.
 *
 * Unlike the ledger note above, this one cannot be stated beforehand: whether a
 * row opens is not known until the pass tries it. The vault is the one store a
 * rotation re-keys rather than invalidates, so a complete pass has nothing to
 * disclose — which is exactly why a partial one must say so rather than let the
 * rotation report unqualified success.
 *
 * A row left at the old epoch still resolves, so no value is lost. What is lost
 * is matchability: the same value detected again fingerprints under the NEW key,
 * misses the stale row, and mints a second pointer for a secret that already has
 * one in circulation.
 *
 * `skipped` of `refreshed + skipped` rather than a bare count: a numerator with
 * no denominator cannot tell "nothing needed refreshing" apart from "every row
 * failed", which is the whole reason this note exists.
 *
 * Returns null for a clean pass, so a caller surfaces exactly what it is given
 * and never has to decide what counts as a shortfall.
 *
 * Both arguments are counts of ROWS, not a report of one particular pass, so the
 * standing condition reads through the same sentence: a store that holds `total`
 * entries of which `stale` are off the current key calls this with
 * `(total - stale, stale)`. That is deliberate — the event and the condition are
 * the same fact, and wording them separately is how two surfaces come to
 * describe one state differently. Hence "an older fingerprint key" rather than
 * "the previous" one: after two rotations a row left behind is two epochs back.
 *
 * It names the REMEDY'S OWN COST rather than saying "re-run the rotation", and
 * that is not politeness. Re-keying these rows has exactly one lever — another
 * rotation — and `rotateFingerprintKey` always mints a HIGHER version, so
 * reaching for it invalidates every grant a second time. A reader told to retry
 * without being told that destroys the grants they re-approved after the first
 * rotation, to repair rows that were resolving fine.
 *
 * It also declines to promise the retry will work. A row is skipped because it
 * could not be OPENED, and that covers two unlike causes the pass cannot tell
 * apart: a key directory that cannot be read right now, which a later rotation
 * does fix, and a damaged entry or a discarded key epoch, which nothing fixes —
 * the plaintext is unrecoverable, so that row stays stale through every future
 * rotation and re-reports itself each time. Hence "find out why" before a second
 * rotation, and pruning named as the answer for the half that will never open.
 *
 * Lives here, beside `rotationBlockedLedgerNote`, for the same reason: `aka
 * exception rotate-key` and the dashboard's rotate action disclose the cost of
 * one irreversible action, and a second copy is how two surfaces come to state
 * different costs for it.
 */
export function vaultRefreshShortfallNote(refreshed: number, skipped: number): string | null {
  if (skipped <= 0) return null;
  const considered = refreshed + skipped;
  const noun = considered === 1 ? 'value' : 'values';
  return `${String(skipped)} of ${String(considered)} stored ${noun} could not be re-keyed and still carry an older fingerprint key. Nothing stored is lost and each one still resolves, but detecting the same value again will miss it and mint a second pointer for a secret that already has one. Only another rotation re-keys them, and rotating again invalidates every exception grant a second time — so find out why the rows will not open before reaching for it. A key directory that cannot be read is worth a second rotation once fixed; a damaged entry will never open again and is better pruned than carried.`;
}

/**
 * The whole-pass version of the note above: the refresh threw before it could
 * report per-row counts, so every stored value is assumed to be at the old
 * epoch.
 *
 * Deliberately claims no number. The throw can come from opening the store, the
 * key custody, or the first row, so the pass does not know how many rows it
 * never reached — and a figure invented here would be the one thing a reader
 * could check and find wrong.
 *
 * Names the remedy's cost for the same reason the note above does: another
 * rotation is the only thing that re-keys these rows, and it invalidates every
 * grant again. A whole-pass fault is the likelier one to be transient — the
 * store or the key custody, rather than any one row — so this variant points at
 * the read before the retry and leaves pruning to the per-row note, which is the
 * only one that can be about a specific unrecoverable entry.
 */
export const VAULT_REFRESH_FAILED_NOTE =
  'The vault could not be re-keyed under the new fingerprint key, so every stored value still carries the previous one. Nothing stored is lost and they all still resolve, but detecting one of them again may mint a second pointer for a secret that already has one. Only another rotation re-keys them, and rotating again invalidates every exception grant a second time — check why the vault could not be read before reaching for it.';
