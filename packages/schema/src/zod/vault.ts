// The reversible secret vault: contracts for the pointer that replaces a
// detected value, the encrypted entry that can give it back, and the audit row
// every de-reference writes.
//
// This is the one store in the product that is REVERSIBLE. Everywhere else a
// detected value is destroyed (`maskMatch`, `[REDACTED:CATEGORY]`) or reduced to
// a keyed one-way fingerprint (`exception.key`). Here the raw value survives as
// AEAD ciphertext so its owner can get it back, while the model only ever holds
// the pointer.
//
// Plugin-local only — deliberately NO `.meta({ id })` on these shapes, for the
// reason WorkspaceSettings documents: an id registers the schema globally, and a
// swagger setup would emit it as an OpenAPI component. Nothing about the vault
// belongs on a public API surface.
import { z } from 'zod';

import { DetectionCategory } from './finding.ts';

// Bumped when the vault's stored shape changes in a way a reader must notice.
export const VAULT_SPEC_VERSION = 1;

// The wire pointer's format generation. Version 1 was the category-free
// `[[aka:tok:...]]` form, which no shipped build ever emitted; version 2 carries
// the category segment. It is covered by the pointer tag and by the AEAD AAD, so
// a pointer cannot be relabelled into a different category.
export const POINTER_FORMAT_VERSION = 2;

// ─── The wire pointer ────────────────────────────────────────────────────────

// `[[aka:<category>:<b32 key_version>.<b32 pointer_id>.<b32 tag>]]`
//
// Segment widths follow from the byte widths, in RFC 4648 base32 without
// padding (5 bits per character):
//   key_version  minimal big-endian bytes  → 2 chars (1 byte) … 7 chars (4 bytes)
//   pointer_id   16 bytes                  → 26 chars, fixed
//   tag          10 bytes                  → 16 chars, fixed
//
// The category alternation is PINNED to the DetectionCategory members rather
// than a permissive `[a-z]+`: a lookalike carrying an invented category must
// fail to parse as a pointer at all, so it can never reach the de-reference path
// or trip an executable-field deny.
const CATEGORY_ALTERNATION = DetectionCategory.options.join('|');

export const POINTER_TOKEN_PATTERN = new RegExp(
  `\\[\\[aka:(?:${CATEGORY_ALTERNATION}):[A-Z2-7]{2,7}\\.[A-Z2-7]{26}\\.[A-Z2-7]{16}\\]\\]`,
);

// The same pattern anchored, for validating a single candidate end to end.
export const POINTER_TOKEN_ANCHORED = new RegExp(`^${POINTER_TOKEN_PATTERN.source}$`);

// A global-flagged clone for scanning text. Built fresh per call: a shared
// /g regex carries mutable `lastIndex` state across calls and would silently
// skip matches.
export function pointerTokenScanner(): RegExp {
  return new RegExp(POINTER_TOKEN_PATTERN.source, 'g');
}

export const PointerToken = z.string().regex(POINTER_TOKEN_ANCHORED);
export type PointerToken = z.infer<typeof PointerToken>;

// The parsed segments of a pointer, before any tag verification. Parsing proves
// only shape — `detokenize` verifies the tag before it touches ciphertext.
export const ParsedPointer = z.object({
  category: DetectionCategory,
  keyVersion: z.number().int().positive(),
  pointerId: z.string(),
  tag: z.string(),
});
export type ParsedPointer = z.infer<typeof ParsedPointer>;

// ─── The vault entry ─────────────────────────────────────────────────────────

// One row per detected VALUE, unique on `valueFingerprint`, so the same secret
// seen twice yields one row and one pointer.
export const VaultEntry = z.object({
  pointerId: z.string(),
  // The keyed HMAC of the raw value under `exception.key`, and the epoch it was
  // derived under. This is what an SP-5 reveal grant matches on, and it rotates
  // independently of the vault encryption key below.
  valueFingerprint: z.string().regex(/^[0-9a-f]{64}$/),
  fingerprintKeyVersion: z.number().int().positive(),
  // The vault-key epoch this row's ciphertext was sealed under.
  keyVersion: z.number().int().positive(),
  // Fixed at first mint and never updated: the same value detected later under a
  // different rule's category keeps the category it was minted with, so one
  // value always produces exactly one wire token.
  category: DetectionCategory,
  ruleId: z.string(),
  // Partial-reveal preview for badges and listings. Never the raw value.
  maskedMatch: z.string(),
  provider: z.string().optional(),
  ciphertext: z.string(),
  nonce: z.string(),
  authTag: z.string(),
  // How many times this value has been detected on this machine — the reuse
  // signal SP-6 reads. Distinct from VaultDeref.pointerCount.
  occurrenceCount: z.number().int().nonnegative(),
  firstSeen: z.string(),
  lastSeen: z.string(),
});
export type VaultEntry = z.infer<typeof VaultEntry>;

// What a presentation surface may know about a pointer without de-referencing
// it. Carries no raw value and no fingerprint — the keyed HMAC is a correlation
// key and must never reach a view layer or the browser.
export const PointerDescriptor = z.object({
  category: DetectionCategory,
  provider: z.string().optional(),
  maskedMatch: z.string(),
  occurrences: z.number().int().nonnegative(),
  firstSeen: z.string(),
  lastSeen: z.string(),
});
export type PointerDescriptor = z.infer<typeof PointerDescriptor>;

// The raw-free vault-row identity a reveal grant matches on. Deliberately NOT
// exported to view surfaces — see PointerDescriptor.
export const PointerIdentity = z.object({
  ruleId: z.string(),
  valueFingerprint: z.string().regex(/^[0-9a-f]{64}$/),
  fingerprintKeyVersion: z.number().int().positive(),
});
export type PointerIdentity = z.infer<typeof PointerIdentity>;

// ─── De-reference audit ──────────────────────────────────────────────────────

export const DetokenizeTarget = z.enum(['human', 'model']);
export type DetokenizeTarget = z.infer<typeof DetokenizeTarget>;

// A CLOSED vocabulary, not a naming convention: the audit view groups on these,
// and a free-form typo would silently drop a crossing out of the view.
//
//   display         a MessageDisplay full-mode render resolved it on screen
//   explicit-reveal the user asked (`aka vault show`, the dashboard, the vault UI)
//   view-render     a dashboard surface resolved it to render a record
//   model-input     a model-echoed pointer was de-referenced back for the model
//   remediation     a transcript/at-rest rewrite path resolved it
//   purge           entries were destroyed, making their pointers unresolvable.
//                   Not a de-reference, but it belongs in the same trail: the
//                   record that values were destroyed has to outlive them.
export const VaultDerefReason = z.enum([
  'display',
  'explicit-reveal',
  'view-render',
  'model-input',
  'remediation',
  'purge',
]);
export type VaultDerefReason = z.infer<typeof VaultDerefReason>;

export const VaultDerefOutcome = z.enum(['revealed', 'refused', 'unavailable']);
export type VaultDerefOutcome = z.infer<typeof VaultDerefOutcome>;

// Reasons whose rows are batched to one per message/render. The model crossings
// are never batched: they are the rows the threat model reads as its anomaly
// signal, and burying them under display volume would defeat that.
export const BATCHED_DEREF_REASONS: readonly VaultDerefReason[] = ['display', 'view-render'];

export function isBatchedDerefReason(reason: VaultDerefReason): boolean {
  return BATCHED_DEREF_REASONS.includes(reason);
}

// One de-reference. Never carries the raw value or the ciphertext.
export const VaultDeref = z.object({
  id: z.guid(),
  pointerId: z.string(),
  at: z.string(),
  target: DetokenizeTarget,
  reason: VaultDerefReason,
  outcome: VaultDerefOutcome,
  // Present only on a model-target crossing that a reveal grant authorized.
  grantId: z.string().optional(),
  // How many pointers ONE batched render resolved. 1 for unbatched rows. Named
  // apart from VaultEntry.occurrenceCount, which counts detections of a value.
  pointerCount: z.number().int().positive().default(1),
});
export type VaultDeref = z.infer<typeof VaultDeref>;

// ─── Settings-side vocabulary ────────────────────────────────────────────────

// Where the vault master key lives. An OPEN discriminant: the custody vocabulary
// is extensible, so a provider name this schema has never heard of must still
// parse — the runtime contract is ANY string and nothing here rejects an unknown
// one. `createKeyProvider` resolves the two names this build implements and
// treats every other value as file custody, so a misspelled 'keychain' parses
// clean and silently yields file custody — the safe direction, but not the one
// the user asked for.
//
// The literals live in the TYPE only, where they give editors completion and keep
// `switch` exhaustiveness meaningful. `(string & {})` is what stops the union from
// collapsing to bare `string` and swallowing them; it validates nothing.
export const VaultKeyCustody: z.ZodType<'file' | 'keychain' | (string & {})> = z.string();
export type VaultKeyCustody = z.infer<typeof VaultKeyCustody>;

// How a pointer renders in assistant prose on screen.
//
//   masked  a `[scrubbed:...]` badge from descriptor data only — no de-reference,
//           no raw value, no audit row. The default.
//   full    the real value plus the badge, capped and never inside fenced or
//           quoted regions.
//   off     display is not modified at all.
//
// `masked` is the default because the model can be induced by injected content
// to echo every pointer it has seen; under `full` those echoes would render real
// secrets on screen, where they are shoulder-surfed or copied elsewhere.
export const VaultInlineReveal = z.enum(['masked', 'full', 'off']);
export type VaultInlineReveal = z.infer<typeof VaultInlineReveal>;

// How many pointers may resolve to raw in ONE assistant message under `full`.
// Bounds a single "dump every pointer" injection to two values.
export const VAULT_INLINE_REVEAL_MAX_PER_MESSAGE = 2;

// Budget for the standing protocol brief injected at session start, in
// estimated tokens (ceil(chars / 4)). The brief is re-read by the model every
// turn, so its cost is paid constantly; the builder truncates rather than
// exceeds.
export const VAULT_BRIEF_TOKEN_BUDGET = 160;

// How many pointers one per-event note enumerates before "… and N more".
export const VAULT_EVENT_NOTE_MAX_POINTERS = 8;

// The behavior the user consented to. A grant recorded against an older version
// stops counting, so widening what the vault does forces a re-ask.
export const VAULT_CONSENT_VERSION = 1;

export const VaultConsent = z.object({
  acknowledgedAt: z.iso.datetime(),
  version: z.number().int().positive(),
});
export type VaultConsent = z.infer<typeof VaultConsent>;

// Whether a recorded grant authorizes vaulting right now. Absent or recorded
// against an older payload version → no vaulting.
export function isVaultConsentValid(consent: VaultConsent | undefined): boolean {
  return consent?.version === VAULT_CONSENT_VERSION;
}
