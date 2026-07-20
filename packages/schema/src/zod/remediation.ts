import { z } from 'zod';

import { Span } from './finding.ts';

// Whether a leaked key still authenticates. `still-valid` keys are the ones the
// remediation flow orders most-exposed-first; `unknown` covers keys that could
// not be checked, `invalid` a key that no longer authenticates.
export const SecretFindingState = z.enum(['still-valid', 'unknown', 'invalid']);
export type SecretFindingState = z.infer<typeof SecretFindingState>;

// Where a leaked key was found: the transcript/temp artifact path plus an
// optional character span within it, enough for the redaction step to locate the
// occurrence. `.strict()` so an unknown key (e.g. a raw-value field) is rejected
// rather than silently stripped.
export const MaskedFindingLocation = z
  .object({
    filePath: z.string(),
    span: Span.optional(),
  })
  .strict();
export type MaskedFindingLocation = z.infer<typeof MaskedFindingLocation>;

// One raw-free summary of a leaked-key finding, as rendered in the finding
// table and referenced by the redaction step: the key's provider, a masked-only
// token, where it was found, and whether it still authenticates. `maskedToken`
// is a maskMatch()-style preview (the same masked-only convention as
// TriageHit.maskedMatch) — never the raw key. `.strict()` is load-bearing: it
// rejects any extra field, so a shape smuggling a raw secret value under an
// unmodeled key fails at the boundary instead of passing through.
//
// No `.meta({ id })` — no API route references this shape, matching the
// CalibrationFrame/TriageHit convention (an unrouted id would still register in
// Zod's global registry and leak an orphan component into the generated OpenAPI
// client).
export const MaskedSecretFinding = z
  .object({
    provider: z.string(),
    maskedToken: z.string(),
    where: MaskedFindingLocation,
    state: SecretFindingState,
    observedAt: z.iso.datetime().optional(),
  })
  .strict();
export type MaskedSecretFinding = z.infer<typeof MaskedSecretFinding>;

// One ordered line in a rotation checklist. The token is a masked-only
// preview, and the console path names either the provider's rotation surface
// or the generic provider-console fallback.
export const RotationChecklistEntry = z
  .object({
    provider: z.string(),
    maskedToken: z.string(),
    consolePath: z.string(),
    occurrenceSpread: z.number().int().positive(),
  })
  .strict();
export type RotationChecklistEntry = z.infer<typeof RotationChecklistEntry>;

// The exactly-four options of the remediation decision, each a stable id the
// prompt layer routes on. The set is closed: a fifth id fails validation.
export const RemediationOption = z.enum([
  'redact-rotation-checklist',
  'redact-only',
  'set-secret-redact',
  'leave',
]);
export type RemediationOption = z.infer<typeof RemediationOption>;

// Where the remediation chain was entered from. Carries no wizard state, so the
// chain is invocable directly with a findings set plus this context — the same
// entry-point-agnostic contract the pre-push and secret-scan entries reuse.
export const RemediationEntrySource = z.enum(['first-run', 'pre-push', 'secret-scan']);
export type RemediationEntrySource = z.infer<typeof RemediationEntrySource>;

// The entry-point-agnostic context the remediation chain is invoked with. Just
// the entry-source tag — `.strict()` rejects any wizard-state field, keeping the
// contract free of frame/onboarding coupling so a direct (non-wizard) caller
// supplies the same shape a first-run entry does.
export const RemediationEntryContext = z
  .object({
    entrySource: RemediationEntrySource,
  })
  .strict();
export type RemediationEntryContext = z.infer<typeof RemediationEntryContext>;

// One offered option of the remediation decision: the stable RemediationOption
// id the prompt layer routes on plus the user-facing label it shows. Mirrors the
// SetupHandoffOption shape (a routed id + its label).
export const RemediationOptionChoice = z.object({
  id: RemediationOption,
  label: z.string(),
});
export type RemediationOptionChoice = z.infer<typeof RemediationOptionChoice>;

// The batched remediation decision presentation model: ONE decision moment
// over all the surfaced secret-leak findings (never one prompt per finding), the
// real `secretCount` its copy templates over, and the exactly-four remediation
// options. `options` is a fixed four-entry tuple — Redact + rotation checklist,
// Redact only, Set 'secret' to redact, Leave — so a dropped, reordered, or extra
// option fails validation, matching the SetupHandoffOffer tuple convention.
// `secretCount` is positive: a decision only exists when at least one secret
// finding surfaced (the empty read degrades to NoRemediationDecision, never a
// zero-count decision). No wizard state, so a harness reads this to assert the
// batched decision without observing the interactive prompt. No `.meta({ id })` —
// no API route references it, matching the CalibrationFrame convention.
export const BatchedRemediationDecision = z.object({
  kind: z.literal('decision'),
  entrySource: RemediationEntrySource,
  secretCount: z.number().int().positive(),
  prompt: z.string(),
  options: z.tuple([
    RemediationOptionChoice.extend({ id: z.literal('redact-rotation-checklist') }),
    RemediationOptionChoice.extend({ id: z.literal('redact-only') }),
    RemediationOptionChoice.extend({ id: z.literal('set-secret-redact') }),
    RemediationOptionChoice.extend({ id: z.literal('leave') }),
  ]),
});
export type BatchedRemediationDecision = z.infer<typeof BatchedRemediationDecision>;

// The honest degraded outcome when no secret-leak finding surfaced: no count is
// fabricated and no remediation decision is presented. `kind: 'no-decision'`
// discriminates it from a real decision.
export const NoRemediationDecision = z.object({
  kind: z.literal('no-decision'),
});
export type NoRemediationDecision = z.infer<typeof NoRemediationDecision>;

// The batched-remediation outcome: either a real remediation decision over surfaced
// secret findings or the honest no-decision degrade. Discriminated on `kind`.
export const BatchedRemediation = z.discriminatedUnion('kind', [
  BatchedRemediationDecision,
  NoRemediationDecision,
]);
export type BatchedRemediation = z.infer<typeof BatchedRemediation>;
