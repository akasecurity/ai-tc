// Detection exceptions: user-approved grants that let one specific detected
// value pass an enforcing (block/redact) policy. The match key is
// (ruleId, valueFingerprint) — the rule is the stable detection identity, and
// the fingerprint pins the grant to the exact value the user approved. A
// value-free, rule-wide suppression is a policy change, not an exception.
import { z } from 'zod';

import { DetectionCategory } from './finding.ts';

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

// Tenant-free base (local store + wire bundle). NO `.meta({ id })`: an id
// would register it in Zod's global registry and leak it into the
// generated OpenAPI client.
// What a grant authorizes. 'suppress' is today's semantics: the detection is
// not hard-enforced (block/redact downgrades). 'reveal_to_model' is strictly
// stronger: the vault may de-reference the value's pointer back to raw FOR THE
// MODEL at an interception point — and, being stronger, it also satisfies
// suppression (a revealed value is necessarily not blocked). A suppression
// grant never reveals: the two are distinct so no existing grant silently
// widens.
export const ExceptionCapability = z.enum(['suppress', 'reveal_to_model']);
export type ExceptionCapability = z.infer<typeof ExceptionCapability>;

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
