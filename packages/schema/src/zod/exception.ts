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
export const ExceptionDescriptor = DetectionException.omit({ valueFingerprint: true });
export type ExceptionDescriptor = z.infer<typeof ExceptionDescriptor>;

/** Strip the keyed fingerprint from a grant row before it crosses to a view. */
export function toExceptionDescriptor(exception: DetectionException): ExceptionDescriptor {
  const descriptor: ExceptionDescriptor & { valueFingerprint?: string } = { ...exception };
  delete descriptor.valueFingerprint;
  return descriptor;
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

// The ledger row minus its keyed fingerprint — the same egress rule as
// ExceptionDescriptor. The approve flows round-trip `reference` and the server
// re-reads the full row, so the fingerprint never needs to leave it.
export type BlockedDetectionDescriptor = Omit<BlockedDetection, 'valueFingerprint'>;

/** Strip the keyed fingerprint from a ledger row before it crosses to a view. */
export function toBlockedDetectionDescriptor(row: BlockedDetection): BlockedDetectionDescriptor {
  const descriptor: BlockedDetectionDescriptor & { valueFingerprint?: string } = { ...row };
  delete descriptor.valueFingerprint;
  return descriptor;
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
